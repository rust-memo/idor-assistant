package com.adminsec.idor;

import com.adminsec.idor.model.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.*;
import java.util.*;

import static com.adminsec.idor.HttpFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.mockStatic;

class RedactionAndExportTest {
    @TempDir Path temp;
    private final RedactionService redaction = new RedactionService();

    @Test void redactsJsonFormAndJwtSecrets() {
        String raw = "{\"password\":\"secret\",\"token\":\"abc\"}&csrf=xyz eyJabcdefgh.abcdefgh.abcdefgh";
        String safe = redaction.redactText(raw);
        assertFalse(safe.contains("secret")); assertFalse(safe.contains("xyz")); assertFalse(safe.contains("eyJabcdefgh"));
        assertTrue(safe.contains("<redacted>"));
    }

    @Test void redactedHttpRemovesAuthenticationAndQueryValues() {
        var request = request("GET", "https://example.test/account?id=12345", "token=secret", true,
                List.of(header("Authorization", "Bearer secret"), header("Cookie", "sid=secret")),
                List.of(parameter("id", "12345", burp.api.montoya.http.message.params.HttpParameterType.URL)));
        var message = message(request, 200, "{\"token\":\"secret\"}", "application/json");
        try (var factory = mockStatic(burp.api.montoya.http.message.HttpRequestResponse.class)) {
            factory.when(() -> burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(request, message.response())).thenReturn(message);
            assertNotNull(redaction.redact(message));
            verify(request).withRemovedHeader("authorization"); verify(request).withRemovedHeader("cookie");
            verify(request, org.mockito.Mockito.atLeastOnce()).withPath("/account");
            verify(request).withBody(org.mockito.ArgumentMatchers.contains("<redacted>"));
        }
    }

    @Test void jsonReportIsMetadataOnlyByDefault() throws Exception {
        Candidate candidate = candidate(); Path path = temp.resolve("report.json");
        new ReportExporter().export(path, List.of(candidate)); String report = Files.readString(path);
        assertFalse(report.contains("Bearer secret")); assertFalse(report.contains("response-secret"));
        assertFalse(report.contains("?id=12345")); assertTrue(report.contains("/accounts/{id}"));
    }

    @Test void optionalEvidenceIsRedactedAndBounded() throws Exception {
        Candidate candidate = candidate(); Path path = temp.resolve("report.html");
        new ReportExporter().export(path, List.of(candidate), true); String report = Files.readString(path);
        assertTrue(report.contains("Redacted evidence")); assertFalse(report.contains("response-secret"));
        assertFalse(report.contains("12345")); assertTrue(report.contains("object-"));
    }

    @Test void csvPreventsFormulaInjection() throws Exception {
        Candidate candidate = candidate(); candidate.reviewStatus("=HYPERLINK(\"bad\")");
        Path path = temp.resolve("report.csv"); new CsvExporter().export(path, List.of(candidate));
        assertTrue(Files.readString(path).contains("'=HYPERLINK"));
    }

    @Test void fingerprintsAreStableAndDoNotRevealRawValues() {
        assertEquals(redaction.fingerprint("12345"), redaction.fingerprint("12345"));
        assertNotEquals("12345", redaction.fingerprint("12345")); assertEquals(12, redaction.fingerprint("12345").length());
    }

    private Candidate candidate() {
        var request = request("GET", "https://example.test/accounts?id=12345", "", true,
                List.of(header("Authorization", "Bearer secret")), List.of());
        Assessment assessment = new Assessment(85, "High", "/accounts/{id}",
                List.of(new Reference("account_id", "12345", "URL", "numeric ID")), List.of("sensitive"));
        Candidate candidate = new Candidate("report", assessment,
                message(request, 200, "{\"account_id\":12345,\"token\":\"response-secret\"}", "application/json"), "New");
        candidate.comparison("Suspicious access", "same object", candidate.message(), candidate.message()); return candidate;
    }
}
