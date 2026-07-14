package com.adminsec.idor;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.adminsec.idor.model.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static com.adminsec.idor.HttpFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ComparisonOrchestratorTest {
    private final List<ComparisonOrchestrator> opened = new ArrayList<>();
    @AfterEach void close() { opened.forEach(ComparisonOrchestrator::close); }

    @Test void singleComparisonSendsOwnerAndCrossAndProducesEvidence() throws Exception {
        Fixture fixture = fixture("GET"); Queue<HttpRequestResponse> responses = new ArrayDeque<>();
        responses.add(fixture.ownerResponse); responses.add(fixture.crossResponse);
        ComparisonOrchestrator runner = runner(request -> responses.remove(), request -> true); runner.configureBatch(20, 0);
        CountDownLatch done = new CountDownLatch(1); AtomicReference<ComparisonEvidence> result = new AtomicReference<>();
        runner.compareSingle(fixture.candidate, fixture.observation, fixture.owner, fixture.target, false,
                value -> { result.set(value); done.countDown(); }, error -> done.countDown());
        assertTrue(done.await(3, TimeUnit.SECONDS)); assertEquals("Suspicious access", result.get().status());
        assertEquals("Suspicious access", fixture.candidate.comparisonStatus());
    }

    @Test void batchEnforcesRequestBudgetAndReusesOwnerControl() throws Exception {
        Fixture fixture = fixture("GET"); AtomicInteger sends = new AtomicInteger();
        ComparisonOrchestrator runner = runner(request -> { sends.incrementAndGet(); return fixture.crossResponse; }, request -> true);
        runner.configureBatch(4, 0); List<ComparisonOrchestrator.ComparisonCase> cases = new ArrayList<>();
        for (int i = 0; i < 8; i++) cases.add(fixture.test(false));
        CountDownLatch done = new CountDownLatch(1); AtomicReference<ComparisonOrchestrator.RunSummary> summary = new AtomicReference<>();
        runner.runBatch(cases, new ListenerAdapter() { @Override public void onStopped(ComparisonOrchestrator.RunSummary value) { summary.set(value); done.countDown(); } });
        assertTrue(done.await(3, TimeUnit.SECONDS)); assertEquals(4, sends.get()); assertTrue(summary.get().stopped());
        assertTrue(summary.get().reason().contains("request budget"));
    }

    @Test void stateChangingRequestsAreNeverSentByBatch() throws Exception {
        Fixture fixture = fixture("POST"); AtomicInteger sends = new AtomicInteger();
        ComparisonOrchestrator runner = runner(request -> { sends.incrementAndGet(); return fixture.crossResponse; }, request -> true);
        CountDownLatch done = new CountDownLatch(1); AtomicReference<String> error = new AtomicReference<>();
        runner.runBatch(List.of(fixture.test(false)), new ListenerAdapter() {
            @Override public void onError(ComparisonOrchestrator.ComparisonCase test, String message) { error.set(message); }
            @Override public void onStopped(ComparisonOrchestrator.RunSummary summary) { done.countDown(); }
        });
        assertTrue(done.await(3, TimeUnit.SECONDS)); assertEquals(0, sends.get()); assertTrue(error.get().contains("GET and HEAD"));
    }

    @Test void scopeIsCheckedBeforeAnyNetworkCall() throws Exception {
        Fixture fixture = fixture("GET"); AtomicInteger sends = new AtomicInteger();
        ComparisonOrchestrator runner = runner(request -> { sends.incrementAndGet(); return fixture.crossResponse; }, request -> false);
        CountDownLatch done = new CountDownLatch(1); AtomicReference<String> error = new AtomicReference<>();
        runner.compareSingle(fixture.candidate, fixture.observation, fixture.owner, fixture.target, false,
                value -> done.countDown(), value -> { error.set(value); done.countDown(); });
        assertTrue(done.await(3, TimeUnit.SECONDS)); assertEquals(0, sends.get()); assertTrue(error.get().contains("Out-of-scope"));
    }

    @Test void rateLimitingStopsTheBatchImmediately() throws Exception {
        Fixture fixture = fixture("GET"); HttpRequestResponse limited = message(fixture.request, 429, "slow down", "application/json");
        Queue<HttpRequestResponse> responses = new ArrayDeque<>(List.of(fixture.ownerResponse, limited));
        ComparisonOrchestrator runner = runner(request -> responses.remove(), request -> true); runner.configureBatch(20, 0);
        CountDownLatch done = new CountDownLatch(1); AtomicReference<ComparisonOrchestrator.RunSummary> summary = new AtomicReference<>();
        runner.runBatch(List.of(fixture.test(false), fixture.test(false)), new ListenerAdapter() {
            @Override public void onStopped(ComparisonOrchestrator.RunSummary value) { summary.set(value); done.countDown(); }
        });
        assertTrue(done.await(3, TimeUnit.SECONDS)); assertEquals(2, summary.get().requestsSent());
        assertTrue(summary.get().reason().contains("429"));
    }

    @Test void rejectsProfilesWithTheSameAuthenticationFingerprint() throws Exception {
        Fixture fixture = fixture("GET"); ComparisonOrchestrator runner = runner(request -> fixture.ownerResponse, request -> true);
        CountDownLatch done = new CountDownLatch(1); AtomicReference<String> error = new AtomicReference<>();
        runner.compareSingle(fixture.candidate, fixture.observation, fixture.owner, fixture.owner, false,
                value -> done.countDown(), value -> { error.set(value); done.countDown(); });
        assertTrue(done.await(3, TimeUnit.SECONDS)); assertTrue(error.get().contains("same authentication"));
    }

    private ComparisonOrchestrator runner(HttpSender sender, ScopeGuard scope) {
        ComparisonOrchestrator value = new ComparisonOrchestrator(sender, scope); opened.add(value); return value;
    }

    private Fixture fixture(String method) {
        var request = request(method, "https://example.test/accounts/12345");
        var original = message(request, 200, "{\"account_id\":12345,\"name\":\"Alice\"}", "application/json");
        Assessment assessment = new Assessment(85, "High", "/accounts/{id}",
                List.of(new Reference("account_id", "12345", "Path", "numeric ID")), List.of("owner"));
        Candidate candidate = new Candidate("case", assessment, original, "New");
        return new Fixture(request, candidate, candidate.observations().get(0),
                IdentityProfile.fromHeaders("Owner", Map.of("Authorization", "Bearer owner")),
                IdentityProfile.fromHeaders("Other", Map.of("Authorization", "Bearer other")),
                message(request, 200, "{\"account_id\":12345,\"name\":\"Alice\"}", "application/json"),
                message(request, 200, "{\"account_id\":12345,\"name\":\"Alice\"}", "application/json"));
    }

    private record Fixture(burp.api.montoya.http.message.requests.HttpRequest request, Candidate candidate,
                           ObjectObservation observation, IdentityProfile owner, IdentityProfile target,
                           HttpRequestResponse ownerResponse, HttpRequestResponse crossResponse) {
        ComparisonOrchestrator.ComparisonCase test(boolean anonymous) {
            return new ComparisonOrchestrator.ComparisonCase(candidate, observation, owner, anonymous ? null : target, anonymous);
        }
    }

    private abstract static class ListenerAdapter implements ComparisonOrchestrator.Listener {
        @Override public void onEvidence(ComparisonOrchestrator.ComparisonCase test, ComparisonEvidence evidence) { }
    }
}
