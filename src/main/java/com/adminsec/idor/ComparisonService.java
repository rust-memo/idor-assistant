package com.adminsec.idor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.adminsec.idor.model.Candidate;

import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Consumer;

public final class ComparisonService implements AutoCloseable {
    private final MontoyaApi api;
    private final ResponseComparator comparator = new ResponseComparator();
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "idor-comparison"); t.setDaemon(true); return t;
    });
    private volatile Future<?> running;

    public ComparisonService(MontoyaApi api) { this.api = api; }
    public void configureVolatileFields(java.util.Collection<String> names) { comparator.configureVolatileFields(names); }

    public synchronized boolean isRunning() { return running != null && !running.isDone(); }
    public synchronized void cancel() { if (running != null) running.cancel(true); }

    public synchronized void compare(Candidate candidate, IdentityProfile owner, IdentityProfile other,
                                     Consumer<Candidate> finished, Consumer<String> failed) {
        if (isRunning()) { failed.accept("Another comparison is already running"); return; }
        if (owner.sameIdentity(other)) { failed.accept("The owner and other-account profiles have the same authentication fingerprint"); return; }
        running = executor.submit(() -> {
            try {
                HttpRequest original = candidate.message().request();
                if (!original.isInScope()) throw new IllegalStateException("Out-of-scope requests are blocked");
                if (owner.headers().isEmpty() || other.headers().isEmpty()) throw new IllegalStateException("Capture both Profile A and Profile B first");
                boolean safe = Set.of("GET", "HEAD").contains(original.method());
                HttpRequestResponse control = safe ? api.http().sendRequest(owner.apply(original)) : candidate.message();
                if (Thread.currentThread().isInterrupted()) return;
                HttpRequestResponse cross = api.http().sendRequest(other.apply(original));
                if (!control.hasResponse() || !cross.hasResponse()) throw new IllegalStateException("One or both requests did not receive a response");
                ResponseComparator.Result result = comparator.compare(
                        control.response().statusCode(), control.response().bodyToString(), cross.response().statusCode(),
                        cross.response().bodyToString(), candidate.assessment().references());
                candidate.comparison(result.status(), result.detail() + String.format("; similarity %.1f%%; confidence %s",
                        result.similarity() * 100, result.confidence()), control, cross);
                finished.accept(candidate);
            } catch (Exception e) { failed.accept(e.getMessage() == null ? e.toString() : e.getMessage()); }
        });
    }

    public synchronized void compareAnonymous(Candidate candidate, IdentityProfile owner,
                                              Consumer<Candidate> finished, Consumer<String> failed) {
        if (isRunning()) { failed.accept("Another comparison is already running"); return; }
        running = executor.submit(() -> {
            try {
                HttpRequest original = candidate.message().request();
                if (!original.isInScope()) throw new IllegalStateException("Out-of-scope requests are blocked");
                if (owner.headers().isEmpty()) throw new IllegalStateException("Capture the owner profile first");
                HttpRequestResponse control = Set.of("GET", "HEAD").contains(original.method())
                        ? api.http().sendRequest(owner.apply(original)) : candidate.message();
                if (Thread.currentThread().isInterrupted()) return;
                HttpRequestResponse anonymous = api.http().sendRequest(IdentityProfile.withoutAuthentication(original));
                if (!control.hasResponse() || !anonymous.hasResponse()) throw new IllegalStateException("One or both requests did not receive a response");
                ResponseComparator.Result result = comparator.compare(control.response().statusCode(), control.response().bodyToString(),
                        anonymous.response().statusCode(), anonymous.response().bodyToString(), candidate.assessment().references());
                String status = "Suspicious access".equals(result.status()) ? "Suspicious anonymous access" : result.status();
                candidate.comparison(status, "Anonymous: " + result.detail() + String.format("; similarity %.1f%%; confidence %s",
                        result.similarity() * 100, result.confidence()), control, anonymous);
                finished.accept(candidate);
            } catch (Exception e) { failed.accept(e.getMessage() == null ? e.toString() : e.getMessage()); }
        });
    }

    @Override public void close() { cancel(); executor.shutdownNow(); }
}
