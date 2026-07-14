package com.adminsec.idor;

import org.junit.jupiter.api.Test;

import java.util.*;

import static com.adminsec.idor.HttpFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ProfileManagerTest {
    @Test void profilesAreMemoryOnlyByDefault() {
        ProjectStore store = mock(ProjectStore.class); when(store.loadSetting("persistProfiles")).thenReturn("false");
        ProfileManager manager = new ProfileManager(store);
        IdentityProfile profile = IdentityProfile.fromHeaders("Alice", Map.of("Authorization", "one")); manager.upsert(profile);
        assertEquals(List.of(profile), manager.all()); verify(store, never()).saveProfiles(any());
        verify(store).clearProfiles();
    }

    @Test void enablingPersistenceSavesAndDisablingClearsSecrets() {
        ProjectStore store = mock(ProjectStore.class); when(store.loadSetting("persistProfiles")).thenReturn("false");
        ProfileManager manager = new ProfileManager(store); manager.upsert(IdentityProfile.fromHeaders("A", Map.of("Cookie", "sid=1")));
        manager.persistenceEnabled(true); assertTrue(manager.persistenceEnabled()); verify(store).saveProfiles(any());
        manager.persistenceEnabled(false); assertFalse(manager.persistenceEnabled()); verify(store, atLeast(2)).clearProfiles();
    }

    @Test void ownerInferenceRequiresExactlyOneMatchingProfile() {
        ProjectStore store = mock(ProjectStore.class); when(store.loadSetting("persistProfiles")).thenReturn("false");
        ProfileManager manager = new ProfileManager(store); IdentityProfile alice = IdentityProfile.fromHeaders("Alice", Map.of("Authorization", "one"));
        manager.upsert(alice); var request = request("GET", "https://example.test/", "", true,
                List.of(header("Authorization", "one")), List.of());
        assertEquals(alice.id(), manager.inferOwner(request).orElseThrow().id());
        manager.upsert(new IdentityProfile(UUID.randomUUID().toString(), "Clone", "", alice.headers(), List.of(), alice.fingerprint()));
        assertTrue(manager.inferOwner(request).isEmpty());
    }

    @Test void persistedProfilesLoadAndCanBeRemoved() {
        ProjectStore store = mock(ProjectStore.class); when(store.loadSetting("persistProfiles")).thenReturn("true");
        IdentityProfile profile = IdentityProfile.fromHeaders("A", Map.of("Cookie", "sid=1")); when(store.loadProfiles()).thenReturn(List.of(profile));
        ProfileManager manager = new ProfileManager(store); assertTrue(manager.find(profile.id()).isPresent());
        manager.remove(profile.id()); assertTrue(manager.all().isEmpty()); verify(store).saveProfiles(any());
    }
}
