package com.adminsec.idor;

import com.adminsec.idor.model.*;
import org.junit.jupiter.api.Test;

import java.util.*;

import static com.adminsec.idor.HttpFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class CandidateCatalogTest {
    @Test void mergesCandidatesAndRetainsDistinctObservations() {
        CandidateCatalog catalog = new CandidateCatalog();
        Candidate first = candidate("https://example.test/users/1", "one");
        Candidate second = candidate("https://example.test/users/2", "two");
        catalog.upsert(first, false); catalog.upsert(second, false);
        assertEquals(1, catalog.all().size()); assertEquals(2, catalog.all().get(0).observations().size());
        assertTrue(catalog.find("key").isPresent());
    }

    @Test void assignsProfileOwnersToMatchingSamples() {
        CandidateCatalog catalog = new CandidateCatalog();
        var request = request("GET", "https://example.test/users/1", "", true,
                List.of(header("Authorization", "Bearer alice")), List.of());
        Candidate candidate = candidate(request, "one"); catalog.upsert(candidate, false);
        IdentityProfile profile = IdentityProfile.fromHeaders("Alice", Map.of("Authorization", "Bearer alice"));
        catalog.assignOwner(profile);
        assertEquals(profile.id(), candidate.observations().get(0).ownerProfileId());
    }

    @Test void capsObservationsAtTwenty() {
        Candidate candidate = candidate("https://example.test/users/0", "0");
        for (int i = 1; i < 30; i++) {
            var extra = candidate("https://example.test/users/" + i, Integer.toString(i));
            extra.observations().forEach(o -> candidate.addObservation(o.message(), o.assessment(), ""));
        }
        assertEquals(20, candidate.observations().size());
    }

    @Test void keepsSuppressedSeparateAndPromotesRepeatedDistinctIdentifiers() {
        CandidateCatalog catalog = new CandidateCatalog();
        Candidate first = suppressedCandidate("https://example.test/widgets/1", "1");
        Candidate second = suppressedCandidate("https://example.test/widgets/2", "2");
        catalog.upsert(first, false);
        assertTrue(catalog.all().isEmpty()); assertEquals(1, catalog.suppressed().size());
        catalog.upsert(second, false);
        assertEquals(1, catalog.all().size()); assertTrue(catalog.suppressed().isEmpty());
        assertTrue(catalog.all().get(0).assessment().reasons().contains("repeated endpoint with distinct observed identifiers"));
    }

    @Test void userCanSuppressAndRestoreWithoutLosingObservations() {
        CandidateCatalog catalog = new CandidateCatalog(); Candidate candidate = candidate("https://example.test/users/1", "one");
        catalog.upsert(candidate, false); catalog.suppress(candidate, "routing identifier");
        assertTrue(catalog.all().isEmpty()); assertEquals("routing identifier", catalog.suppressed().get(0).assessment().dispositionReason());
        catalog.restore(candidate);
        assertEquals(1, catalog.all().size()); assertTrue(catalog.suppressed().isEmpty());
    }

    private Candidate candidate(String url, String body) { return candidate(request("GET", url), body); }
    private Candidate suppressedCandidate(String url, String id) {
        var request = request("GET", url);
        Assessment assessment = new Assessment(45, "Low", "/widgets/{id}",
                List.of(new Reference("widget_id", id, "Path", "numeric ID")), List.of("weak"),
                CandidateDisposition.SUPPRESSED, "Insufficient evidence");
        return new Candidate("weak-key", assessment, message(request, 200, "{}", "application/json"), "New");
    }
    private Candidate candidate(burp.api.montoya.http.message.requests.HttpRequest request, String body) {
        Assessment assessment = new Assessment(70, "Medium", "/users/{id}",
                List.of(new Reference("id", request.url().substring(request.url().lastIndexOf('/') + 1), "Path", "numeric ID")), List.of("id"));
        return new Candidate("key", assessment, message(request, 200, "{\"id\":" + body.hashCode() + "}", "application/json"), "New");
    }
}
