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

    private Candidate candidate(String url, String body) { return candidate(request("GET", url), body); }
    private Candidate candidate(burp.api.montoya.http.message.requests.HttpRequest request, String body) {
        Assessment assessment = new Assessment(70, "Medium", "/users/{id}",
                List.of(new Reference("id", request.url().substring(request.url().lastIndexOf('/') + 1), "Path", "numeric ID")), List.of("id"));
        return new Candidate("key", assessment, message(request, 200, "{\"id\":" + body.hashCode() + "}", "application/json"), "New");
    }
}
