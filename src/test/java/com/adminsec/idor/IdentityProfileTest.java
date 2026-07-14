package com.adminsec.idor;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.HttpParameter;
import org.mockito.MockedStatic;
import org.junit.jupiter.api.Test;

import java.util.*;

import static com.adminsec.idor.HttpFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityProfileTest {
    @Test void capturesAuthenticationAndSessionBoundParameters() {
        var request = request("POST", "https://example.test/update", "", true,
                List.of(header("Authorization", "Bearer one"), header("X-CSRF-Token", "csrf-one"), header("Accept", "json")),
                List.of(parameter("csrf_token", "form-one", HttpParameterType.BODY), parameter("id", "7", HttpParameterType.BODY)));
        IdentityProfile profile = IdentityProfile.capture("Alice", request);
        assertEquals(2, profile.headers().size()); assertEquals(1, profile.substitutions().size());
        assertEquals("csrf_token", profile.substitutions().get(0).name());
    }

    @Test void appliesIdentityAndSessionSubstitutions() {
        var request = request("POST", "https://example.test/update", "", true,
                List.of(header("Authorization", "old")), List.of(parameter("csrf_token", "old", HttpParameterType.BODY)));
        IdentityProfile profile = IdentityProfile.create("Bob", "user", Map.of("Authorization", "Bearer two"),
                List.of(new SessionSubstitution(SessionSubstitution.Location.BODY, "csrf_token", "new")));
        HttpParameter replacement = mock(HttpParameter.class);
        try (MockedStatic<HttpParameter> parameters = mockStatic(HttpParameter.class)) {
            parameters.when(() -> HttpParameter.parameter("csrf_token", "new", HttpParameterType.BODY)).thenReturn(replacement);
            profile.apply(request);
            verify(request).withRemovedHeader("Authorization");
            verify(request).withAddedHeader("Authorization", "Bearer two");
            verify(request).withUpdatedParameters(any(HttpParameter[].class));
        }
    }

    @Test void matchesOnlyTheCapturedAuthenticationValues() {
        IdentityProfile profile = IdentityProfile.fromHeaders("A", Map.of("Authorization", "Bearer one"));
        assertTrue(profile.matches(request("GET", "https://example.test/", "", true,
                List.of(header("authorization", "Bearer one")), List.of())));
        assertFalse(profile.matches(request("GET", "https://example.test/", "", true,
                List.of(header("authorization", "Bearer other")), List.of())));
    }

    @Test void fingerprintsAreStableButSeparateDifferentIdentities() {
        IdentityProfile first = IdentityProfile.fromHeaders("A", Map.of("Cookie", "sid=1", "Authorization", "x"));
        IdentityProfile reordered = IdentityProfile.fromHeaders("A2", new LinkedHashMap<>(Map.of("Authorization", "x", "Cookie", "sid=1")));
        IdentityProfile other = IdentityProfile.fromHeaders("B", Map.of("Cookie", "sid=2", "Authorization", "x"));
        assertTrue(first.sameIdentity(reordered)); assertFalse(first.sameIdentity(other));
        assertTrue(first.display().contains(first.fingerprint().substring(0, 10)));
    }

    @Test void emptyProfilesAreNotConsideredTheSameIdentity() {
        assertFalse(IdentityProfile.fromHeaders("A", Map.of()).sameIdentity(IdentityProfile.fromHeaders("B", Map.of())));
    }
}
