package com.adminsec.idor;

import burp.api.montoya.persistence.PersistedObject;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ProjectStoreV3Test {
    @Test void profileRoundTripPreservesIdsRolesHeadersAndSubstitutions() {
        Backing backing = backing(); ProjectStore store = new ProjectStore(backing.data());
        IdentityProfile expected = new IdentityProfile("profile-id", "Alice", "tenant-a", Map.of("Authorization", "Bearer one"),
                List.of(new SessionSubstitution(SessionSubstitution.Location.BODY, "csrf_token", "csrf-one")), "");
        store.saveProfiles(List.of(expected)); IdentityProfile loaded = store.loadProfiles().get(0);
        assertEquals(expected.id(), loaded.id()); assertEquals("tenant-a", loaded.role());
        assertEquals(expected.headers(), loaded.headers()); assertEquals(expected.substitutions(), loaded.substitutions());
        assertEquals("3", backing.strings().get("schemaVersion"));
    }

    @Test void legacyProfilesMigrateOnlyWhenPersistenceWasEnabled() {
        Backing backing = backing(); ProjectStore store = new ProjectStore(backing.data());
        store.saveSetting("persistProfiles", "true");
        store.saveProfile("A", IdentityProfile.fromHeaders("Alice", Map.of("Cookie", "sid=one")));
        List<IdentityProfile> migrated = store.loadProfiles();
        assertEquals(1, migrated.size()); assertEquals("Alice", migrated.get(0).name());
        assertTrue(backing.strings().containsKey("v3.profiles")); assertFalse(backing.strings().containsKey("profile.A"));
    }

    @Test void corruptProfileDataFailsClosedWithoutExposingPartialSecrets() {
        Backing backing = backing(); backing.strings().put("v3.profiles", "not-json");
        assertTrue(new ProjectStore(backing.data()).loadProfiles().isEmpty());
    }

    @Test void comparisonAndReviewStateRoundTrip() {
        Backing backing = backing(); ProjectStore store = new ProjectStore(backing.data());
        store.saveReviewStatus("candidate", "Confirmed"); store.saveComparison("candidate", "Suspicious access", "detail");
        assertEquals("Confirmed", store.loadReviewStatus("candidate"));
        assertArrayEquals(new String[]{"Suspicious access", "detail"}, store.loadComparison("candidate"));
        assertArrayEquals(new String[]{"Not tested", ""}, store.loadComparison("missing"));
    }

    private Backing backing() {
        Map<String, String> strings = new HashMap<>(); PersistedObject data = mock(PersistedObject.class);
        when(data.getString(anyString())).thenAnswer(invocation -> strings.get(invocation.getArgument(0)));
        doAnswer(invocation -> { strings.put(invocation.getArgument(0), invocation.getArgument(1)); return null; })
                .when(data).setString(anyString(), anyString());
        doAnswer(invocation -> { strings.remove(invocation.getArgument(0)); return null; }).when(data).deleteString(anyString());
        when(data.getBoolean(anyString())).thenReturn(false);
        return new Backing(data, strings);
    }

    private record Backing(PersistedObject data, Map<String, String> strings) { }
}
