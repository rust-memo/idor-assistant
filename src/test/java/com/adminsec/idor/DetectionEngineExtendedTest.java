package com.adminsec.idor;

import com.adminsec.idor.model.Reference;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class DetectionEngineExtendedTest {
    private final DetectionEngine engine = new DetectionEngine();

    @Test void detectsXmlElementsAndAttributesWithoutResolvingEntities() {
        String xml = "<!DOCTYPE x [<!ENTITY ext SYSTEM 'file:///etc/passwd'>]><root accountId='42'><document_id>88</document_id><x>&ext;</x></root>";
        var result = analyze(xml, List.of()).orElseThrow();
        assertTrue(result.references().stream().anyMatch(r -> r.location().equals("XML_ATTRIBUTE") && r.value().equals("42")));
        assertTrue(result.references().stream().anyMatch(r -> r.location().equals("XML") && r.value().equals("88")));
        assertTrue(result.references().stream().noneMatch(r -> r.value().contains("root:")));
    }

    @Test void detectsCookieMultipartAndXmlParametersFromMontoya() {
        List<Reference> parameters = List.of(new Reference("document_id", "12", "COOKIE", ""),
                new Reference("owner_id", "99", "MULTIPART_ATTRIBUTE", ""), new Reference("invoice_id", "77", "XML", ""));
        var result = analyze("", parameters).orElseThrow();
        assertEquals(3, result.references().stream().filter(r -> r.source().equals("Request")).count());
    }

    @Test void customAllowDenyAndPathsAreApplied() {
        engine.configure(List.of("widget"), List.of("owner_id"), List.of("/health"));
        assertTrue(engine.isIdentifierName("widget")); assertFalse(engine.isIdentifierName("owner_id"));
        assertTrue(engine.analyze(input("/health/widgets/12", List.of(new Reference("widget", "12", "URL", "")), "")).isEmpty());
    }

    @Test void oversizedBodiesAreSkippedButUrlReferencesRemain() {
        engine.configureLimits(16_384, 16_384);
        String huge = "x".repeat(20_000) + "{\"account_id\":9}";
        var result = engine.analyze(input("/orders", List.of(new Reference("order_id", "1", "URL", "")), huge)).orElseThrow();
        assertEquals(1, result.references().stream().filter(r -> r.source().equals("Request")).count());
    }

    @Test void graphqlVariablesAndInlineArgumentsAreDetected() {
        String body = "{\"query\":\"query { user(userId: 99) { id } }\",\"variables\":{\"accountId\":42}}";
        var result = analyze(body, List.of()).orElseThrow();
        assertTrue(result.references().stream().anyMatch(r -> r.location().equals("GraphQL")));
        assertTrue(result.references().stream().anyMatch(r -> r.structuralPath().equals("$.variables.accountId")));
    }

    @Test void malformedStructuredBodiesDoNotFailAnalysis() {
        assertDoesNotThrow(() -> analyze("{not-json", List.of(new Reference("id", "3", "URL", ""))));
        assertDoesNotThrow(() -> analyze("<root><id>", List.of(new Reference("id", "3", "URL", ""))));
    }

    private Optional<com.adminsec.idor.model.Assessment> analyze(String body, List<Reference> parameters) {
        return engine.analyze(input("/api/accounts", parameters, body));
    }
    private DetectionEngine.Input input(String path, List<Reference> parameters, String body) {
        return new DetectionEngine.Input("GET", "https://example.test" + path, path, Map.of(), parameters, body, "", 200);
    }
}
