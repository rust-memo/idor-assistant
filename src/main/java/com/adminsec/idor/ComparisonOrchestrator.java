package com.adminsec.idor;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.idor.model.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Sequential, scope-bound comparison runner. Passive analysis never references this sender. */
public final class ComparisonOrchestrator implements AutoCloseable {
    public record ComparisonCase(Candidate candidate, ObjectObservation observation,
                                 IdentityProfile owner, IdentityProfile target, boolean anonymous) { }
    public record RunSummary(int casesCompleted, int requestsSent, boolean stopped, String reason) { }
    public interface Listener {
        void onEvidence(ComparisonCase test, ComparisonEvidence evidence);
        default void onProgress(int completed, int total, int requestsSent) { }
        default void onStopped(RunSummary summary) { }
        default void onError(ComparisonCase test, String message) { }
    }

    private final HttpSender sender;
    private final ScopeGuard scope;
    private final ResponseEvidenceComparator comparator;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "idor-comparison-v3"); thread.setDaemon(true); return thread;
    });
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile Future<?> running;
    private volatile int requestBudget = 20;
    private volatile long delayMillis = 250;

    public ComparisonOrchestrator(HttpSender sender, ScopeGuard scope) {
        this(sender, scope, new ResponseEvidenceComparator());
    }

    ComparisonOrchestrator(HttpSender sender, ScopeGuard scope, ResponseEvidenceComparator comparator) {
        this.sender = Objects.requireNonNull(sender); this.scope = Objects.requireNonNull(scope);
        this.comparator = Objects.requireNonNull(comparator);
    }

    public void configureVolatileFields(Collection<String> names) { comparator.configureVolatileFields(names); }
    public void configureBatch(int budget, long delayMillis) {
        this.requestBudget = Math.max(2, Math.min(budget, 100));
        this.delayMillis = Math.max(0, Math.min(delayMillis, 5_000));
    }
    public synchronized boolean isRunning() { return running != null && !running.isDone(); }
    public synchronized void cancel() { cancelled.set(true); if (running != null) running.cancel(true); }

    public synchronized void runBatch(List<ComparisonCase> requested, Listener listener) {
        if (isRunning()) { listener.onStopped(new RunSummary(0, 0, true, "Another comparison is already running")); return; }
        List<ComparisonCase> cases = List.copyOf(requested == null ? List.of() : requested);
        cancelled.set(false);
        running = executor.submit(() -> executeBatch(cases, listener));
    }

    public synchronized void compareSingle(Candidate candidate, ObjectObservation observation,
                                           IdentityProfile owner, IdentityProfile target, boolean anonymous,
                                           Consumer<ComparisonEvidence> finished, Consumer<String> failed) {
        if (isRunning()) { failed.accept("Another comparison is already running"); return; }
        cancelled.set(false);
        running = executor.submit(() -> {
            try {
                int[] sent = {0};
                ComparisonEvidence evidence = executeCase(new ComparisonCase(candidate, observation, owner, target, anonymous),
                        new HashMap<>(), sent, false);
                apply(candidate, evidence); finished.accept(evidence);
            } catch (Exception e) { failed.accept(message(e)); }
        });
    }

    private void executeBatch(List<ComparisonCase> cases, Listener listener) {
        int completed = 0; int[] sent = {0}; int authenticationFailures = 0;
        Map<String, HttpRequestResponse> ownerCache = new HashMap<>();
        String stopReason = "Completed";
        try {
            for (ComparisonCase test : cases) {
                checkCancelled();
                HttpRequest request = request(test);
                if (!Set.of("GET", "HEAD").contains(request.method().toUpperCase(Locale.ROOT))) {
                    listener.onError(test, "Batch comparisons allow GET and HEAD only"); continue;
                }
                try {
                    ComparisonEvidence evidence = executeCase(test, ownerCache, sent, true);
                    apply(test.candidate(), evidence); listener.onEvidence(test, evidence); completed++;
                    if (evidence.crossAccount() != null && evidence.crossAccount().hasResponse()
                            && evidence.crossAccount().response().statusCode() == 429) {
                        stopReason = "Stopped after HTTP 429 rate limiting"; break;
                    }
                    authenticationFailures = comparator.authenticationFailure(evidence) ? authenticationFailures + 1 : 0;
                    if (authenticationFailures >= 3) { stopReason = "Stopped after three consecutive authentication/session failures"; break; }
                    listener.onProgress(completed, cases.size(), sent[0]);
                } catch (BudgetExhausted e) { stopReason = e.getMessage(); break; }
                catch (Exception e) { listener.onError(test, message(e)); }
            }
        } catch (CancellationException ignored) { stopReason = "Cancelled"; }
        listener.onStopped(new RunSummary(completed, sent[0], completed < cases.size(), stopReason));
    }

    private ComparisonEvidence executeCase(ComparisonCase test, Map<String, HttpRequestResponse> ownerCache,
                                           int[] sent, boolean batch) throws Exception {
        validate(test);
        HttpRequest original = request(test);
        boolean readOnly = Set.of("GET", "HEAD").contains(original.method().toUpperCase(Locale.ROOT));
        if (batch && !readOnly) throw new IllegalStateException("State-changing requests are blocked from Batch");

        HttpRequestResponse ownerControl;
        if (readOnly) {
            String cacheKey = test.observation().id() + "\u0000" + test.owner().id();
            ownerControl = ownerCache.get(cacheKey);
            if (ownerControl == null) {
                ownerControl = send(test.owner().apply(original), sent);
                ownerCache.put(cacheKey, ownerControl);
            }
        } else ownerControl = test.observation().message();
        checkCancelled();
        HttpRequest crossRequest = test.anonymous() ? IdentityProfile.withoutAuthentication(original) : test.target().apply(original);
        HttpRequestResponse cross = send(crossRequest, sent);
        return comparator.compare(test.observation().message(), ownerControl, cross,
                test.observation().assessment().references());
    }

    private HttpRequestResponse send(HttpRequest request, int[] sent) throws Exception {
        checkCancelled();
        if (!scope.isAllowed(request)) throw new IllegalStateException("Out-of-scope requests are blocked");
        if (sent[0] >= requestBudget) throw new BudgetExhausted("Stopped at the " + requestBudget + " request budget");
        if (sent[0] > 0 && delayMillis > 0) Thread.sleep(delayMillis);
        checkCancelled(); sent[0]++;
        return sender.send(request);
    }

    private void validate(ComparisonCase test) {
        if (test == null || test.candidate() == null || test.observation() == null || test.owner() == null)
            throw new IllegalArgumentException("Candidate, observation, and owner profile are required");
        if (test.owner().headers().isEmpty()) throw new IllegalStateException("The owner profile has no captured authentication");
        if (!test.anonymous()) {
            if (test.target() == null || test.target().headers().isEmpty()) throw new IllegalStateException("The target profile has no captured authentication");
            if (test.owner().sameIdentity(test.target())) throw new IllegalStateException("Owner and target profiles have the same authentication fingerprint");
        }
        if (!scope.isAllowed(request(test))) throw new IllegalStateException("Out-of-scope requests are blocked");
    }

    private HttpRequest request(ComparisonCase test) { return test.observation().message().request(); }
    private void apply(Candidate candidate, ComparisonEvidence evidence) {
        candidate.comparison(evidence.status(), evidence.detail() + String.format(Locale.ROOT,
                "; similarity %.1f%%; baseline %.1f%%; confidence %s",
                evidence.similarity() * 100, evidence.baselineStability() * 100, evidence.confidence()),
                evidence.ownerControl(), evidence.crossAccount());
    }
    private void checkCancelled() { if (cancelled.get() || Thread.currentThread().isInterrupted()) throw new CancellationException(); }
    private String message(Exception error) { return error.getMessage() == null ? error.toString() : error.getMessage(); }
    @Override public void close() { cancel(); executor.shutdownNow(); }
    private static final class BudgetExhausted extends Exception { private BudgetExhausted(String message) { super(message); } }
}
