package com.adminsec.idor;

import com.adminsec.idor.model.Reference;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.adminsec.idor.HttpFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ResponseEvidenceComparatorTest {
    private final ResponseEvidenceComparator comparator = new ResponseEvidenceComparator();

    @Test void returnsStrongEvidenceForStableJsonOwnership() {
        var request = request("GET", "https://example.test/accounts/12345");
        var original = message(request, 200, "{\"account_id\":12345,\"name\":\"Alice\",\"nonce\":1}", "application/json");
        var owner = message(request, 200, "{\"name\":\"Alice\",\"account_id\":12345,\"nonce\":2}", "application/json");
        var cross = message(request, 200, "{\"account_id\":12345,\"name\":\"Alice\",\"nonce\":3}", "application/json");
        var evidence = comparator.compare(original, owner, cross,
                List.of(new Reference("account_id", "12345", "Path", "numeric ID")));
        assertEquals("Suspicious access", evidence.status(), evidence.toString()); assertTrue(evidence.ownershipEvidence(), evidence.toString());
        assertTrue(evidence.baselineStability() > .9); assertEquals("High", evidence.confidence());
    }

    @Test void contentTypeChangesAreInconclusive() {
        var request = request("GET", "https://example.test/x/12345");
        var owner = message(request, 200, "{\"id\":12345}", "application/json");
        var cross = message(request, 200, "<html>login</html>", "text/html");
        assertTrue(comparator.compare(owner, owner, cross, List.of()).detail().contains("different content types"));
    }

    @Test void unstableOwnerBaselineDowngradesSuspiciousAccess() {
        var request = request("GET", "https://example.test/x/12345");
        var original = message(request, 200, "{\"id\":12345,\"data\":\"completely old\"}", "application/json");
        var owner = message(request, 200, "{\"id\":12345,\"data\":\"new content with many fields\",\"items\":[1,2,3,4]}", "application/json");
        var cross = message(request, 200, "{\"id\":12345,\"data\":\"new content with many fields\",\"items\":[1,2,3,4]}", "application/json");
        var evidence = comparator.compare(original, owner, cross, List.of(new Reference("id", "12345", "Path", "numeric ID")));
        assertEquals("Inconclusive", evidence.status()); assertTrue(evidence.indicators().contains("unstable owner baseline"));
    }

    @Test void xmlIdentityCanProvideOwnershipEvidence() {
        var request = request("GET", "https://example.test/accounts/12345");
        String body = "<account><account_id>12345</account_id><name>Alice</name></account>";
        var evidence = comparator.compare(message(request, 200, body, "application/xml"),
                message(request, 200, body, "application/xml"), message(request, 200, body, "text/xml"),
                List.of(new Reference("account_id", "12345", "Path", "numeric ID")));
        assertTrue(evidence.ownershipEvidence()); assertEquals("Suspicious access", evidence.status());
    }

    @Test void htmlNormalizationIgnoresMarkupOnlyDifferences() {
        var request = request("GET", "https://example.test/profile/12345");
        var evidence = comparator.compare(null,
                message(request, 200, "<html><body><p>Account 12345</p></body></html>", "text/html"),
                message(request, 200, "<div>Account <b>12345</b></div>", "text/html"), List.of());
        assertTrue(evidence.similarity() > .8); assertEquals("Low", evidence.confidence());
    }

    @Test void sessionFailuresAreRecognizedForBatchStopPolicy() {
        var request = request("GET", "https://example.test/x/12345");
        var evidence = comparator.compare(null, message(request, 200, "{\"id\":12345}", "application/json"),
                message(request, 403, "Invalid CSRF token", "text/plain"), List.of());
        assertTrue(comparator.authenticationFailure(evidence));
    }
}
