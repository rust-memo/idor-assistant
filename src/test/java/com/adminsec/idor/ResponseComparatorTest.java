package com.adminsec.idor;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ResponseComparatorTest {
    private final ResponseComparator comparator = new ResponseComparator();

    @Test void similarSuccessfulResponsesAreSuspicious() {
        var result = comparator.compare(200, "{\"id\":1,\"name\":\"Alice\",\"timestamp\":1}", 200,
                "{\"id\":1,\"name\":\"Alice\",\"timestamp\":2}");
        assertEquals("Suspicious access", result.status());
        assertTrue(result.similarity() > .85);
    }

    @Test void explicitDenialIsProtected() {
        assertEquals("Likely protected", comparator.compare(200, "secret", 403, "Access denied").status());
        assertEquals("Likely protected", comparator.compare(200, "secret", 404, "missing").status());
    }

    @Test void csrfFailureIsInconclusiveNotProtected() {
        assertEquals("Inconclusive", comparator.compare(200, "ok", 403, "Invalid CSRF token").status());
    }

    @Test void similarGenericSuccessWithoutOwnershipIsInconclusive() {
        var result = comparator.compare(200, "{\"ok\":true,\"message\":\"done\"}", 200, "{\"message\":\"done\",\"ok\":true}");
        assertEquals("Inconclusive", result.status());
        assertFalse(result.ownershipEvidence());
    }

    @Test void ignoresConfiguredVolatileJsonFieldsStructurally() {
        comparator.configureVolatileFields(java.util.List.of("buildNumber"));
        var result = comparator.compare(200, "{\"id\":7,\"buildNumber\":1,\"name\":\"x\"}",
                200, "{\"name\":\"x\",\"buildNumber\":999,\"id\":7}");
        assertEquals("Suspicious access", result.status());
        assertEquals(1.0, result.similarity());
    }

    @Test void loginWafAndRateLimitAreInconclusive() {
        assertEquals("Inconclusive", comparator.compare(200, "{\"id\":1}", 200, "<form action='/login'><input name='password'>").status());
        assertEquals("Inconclusive", comparator.compare(200, "{\"id\":1}", 403, "Request blocked by web application firewall").status());
        assertEquals("Inconclusive", comparator.compare(200, "{\"id\":1}", 429, "slow down").status());
    }
}
