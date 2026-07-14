package com.adminsec.idor;

import com.adminsec.idor.model.CandidateDisposition;
import com.adminsec.idor.model.Reference;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Synthetic, redacted corpus for common passive-discovery noise. */
class FalsePositiveCorpusTest {
    private final DetectionEngine engine = new DetectionEngine();

    @Test void operationalIdentifiersDoNotCreateCandidates() {
        List<NoiseCase> corpus = List.of(
                new NoiseCase("/api/status", "request_id", "1234567890123456", "URL"),
                new NoiseCase("/api/status", "trace_id", "507f1f77bcf86cd799439011", "URL"),
                new NoiseCase("/api/status", "version_id", "12", "URL"),
                new NoiseCase("/api/status", "build_id", "998", "JSON/body"),
                new NoiseCase("/api/status", "device_id", "550e8400-e29b-41d4-a716-446655440000", "COOKIE"),
                new NoiseCase("/api/search", "cursor_id", "123", "URL"),
                new NoiseCase("/api/search", "page_id", "4", "URL")
        );
        for (NoiseCase value : corpus) assertTrue(analyze(value.path(),
                List.of(new Reference(value.name(), value.value(), value.location(), "")), "").isEmpty(), value.name());
    }

    @Test void numericOperationalPathsAndYearsAreDiscarded() {
        for (String path : List.of("/api/status/12345", "/metrics/98765", "/api/v1/build/883", "/reports/2026"))
            assertTrue(analyze(path, List.of(), "").isEmpty(), path);
    }

    @Test void unrelatedResponseIdsDoNotPromoteAGenericRequestId() {
        var result = analyze("/api/status", List.of(new Reference("id", "123", "URL", "")),
                "{\"order_id\":987}").orElseThrow();
        assertEquals(CandidateDisposition.SUPPRESSED, result.disposition());
        assertFalse(result.reasons().contains("request reference correlated with response"));
    }

    @Test void strongObjectReferencesRemainActiveAcrossFormats() {
        List<NoiseCase> positives = List.of(
                new NoiseCase("/api/orders", "order_id", "123", "URL"),
                new NoiseCase("/api/documents", "document_id", "507f1f77bcf86cd799439011", "JSON/body"),
                new NoiseCase("/api/files", "file_id", "550e8400-e29b-41d4-a716-446655440000", "MULTIPART_ATTRIBUTE")
        );
        for (NoiseCase value : positives) assertEquals(CandidateDisposition.ACTIVE, analyze(value.path(),
                List.of(new Reference(value.name(), value.value(), value.location(), "")), "").orElseThrow().disposition(), value.name());
    }

    private java.util.Optional<com.adminsec.idor.model.Assessment> analyze(String path, List<Reference> refs, String response) {
        return engine.analyze(new DetectionEngine.Input("GET", "https://example.test" + path, path,
                Map.of(), refs, "", response, 200));
    }

    private record NoiseCase(String path, String name, String value, String location) { }
}
