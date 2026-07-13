package com.adminsec.idor;

import com.adminsec.idor.model.Reference;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class DetectionEngineTest {
    private final DetectionEngine engine = new DetectionEngine();

    @Test void detectsNamedPathJsonGraphqlAndHeaderReferences() {
        var input = new DetectionEngine.Input("PATCH", "https://example.test/api/users/12345/orders/550e8400-e29b-41d4-a716-446655440000",
                "/api/users/12345/orders/550e8400-e29b-41d4-a716-446655440000", Map.of("X-Tenant-ID", "88"),
                List.of(new Reference("account_id", "42", "URL", "")),
                "{\"documentId\":\"507f1f77bcf86cd799439011\",\"query\":\"query { user(userId: 99) { id } }\"}", "{\"invoice_id\":77}", 200);
        var result = engine.analyze(input).orElseThrow();
        assertEquals("High", result.priority());
        assertTrue(result.references().stream().anyMatch(r -> r.location().equals("Path")));
        assertTrue(result.references().stream().anyMatch(r -> r.location().equals("GraphQL")));
        assertTrue(result.references().stream().anyMatch(r -> r.location().equals("Header")));
        assertEquals("/api/users/{id}/orders/{id}", result.endpointTemplate());
    }

    @Test void genericDomainIdsAreCoveredAndNoiseIsIgnored() {
        assertTrue(engine.isIdentifierName("shipment_id"));
        assertTrue(engine.isIdentifierName("warehouse-uuid"));
        assertFalse(engine.isIdentifierName("session_id"));
        assertFalse(engine.isIdentifierName("trace_id"));
        assertFalse(engine.isIdentifierName("csrf_token"));
    }

    @Test void staticAssetsAndYearPathsDoNotCreateCandidates() {
        assertTrue(engine.analyze(input("/assets/app.js", List.of(new Reference("id", "1", "URL", "")))).isEmpty());
        assertTrue(engine.analyze(input("/reports/2026", List.of())).isEmpty());
    }

    @Test void identifiesSnowflakeUlidAndObjectId() {
        assertEquals("Snowflake/numeric ID", engine.shape("123456789012345678"));
        assertEquals("ULID", engine.shape("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
        assertEquals("hex/object ID", engine.shape("507f1f77bcf86cd799439011"));
    }

    @Test void parsesNestedJsonArraysCamelCaseAndKeepsResponseProvenance() {
        var result = engine.analyze(new DetectionEngine.Input("POST", "https://example.test/api/documents", "/api/documents",
                Map.of(), List.of(), "{\"items\":[{\"documentId\":\"507f1f77bcf86cd799439011\"}],\"variables\":{\"accountId\":42}}",
                "{\"data\":{\"ownerId\":42}}", 200)).orElseThrow();
        assertTrue(result.references().stream().anyMatch(r -> r.name().equals("documentId") && r.structuralPath().equals("$.items[0].documentId")));
        assertTrue(result.references().stream().anyMatch(r -> r.name().equals("accountId") && r.source().equals("Request")));
        assertTrue(result.references().stream().anyMatch(r -> r.name().equals("ownerId") && r.source().equals("Response")));
    }

    @Test void camelCaseIdentifierNamesAreRecognized() {
        assertTrue(engine.isIdentifierName("documentId"));
        assertTrue(engine.isIdentifierName("tenantUUID"));
    }

    private DetectionEngine.Input input(String path, List<Reference> refs) {
        return new DetectionEngine.Input("GET", "https://example.test" + path, path, Map.of(), refs, "", "", 200);
    }
}
