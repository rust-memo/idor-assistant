package com.adminsec.idor;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/** Owns identity profiles and keeps secrets memory-only unless explicitly persisted. */
public final class ProfileManager {
    private final ProjectStore store;
    private final Map<String, IdentityProfile> profiles = new LinkedHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private volatile boolean persistenceEnabled;

    public ProfileManager(ProjectStore store) {
        this.store = Objects.requireNonNull(store);
        persistenceEnabled = Boolean.parseBoolean(store.loadSetting("persistProfiles"));
        if (persistenceEnabled) store.loadProfiles().forEach(profile -> profiles.put(profile.id(), profile));
        else store.clearProfiles();
    }

    public synchronized List<IdentityProfile> all() { return List.copyOf(profiles.values()); }
    public synchronized Optional<IdentityProfile> find(String id) { return Optional.ofNullable(profiles.get(id)); }

    public synchronized IdentityProfile add(String name, String role, HttpRequest request) {
        IdentityProfile captured = IdentityProfile.capture(name, request);
        IdentityProfile profile = new IdentityProfile(captured.id(), captured.name(), role, captured.headers(),
                captured.substitutions(), captured.fingerprint());
        profiles.put(profile.id(), profile); saveIfEnabled(); changed(); return profile;
    }

    public synchronized void upsert(IdentityProfile profile) {
        profiles.put(profile.id(), profile); saveIfEnabled(); changed();
    }

    public synchronized void remove(String id) {
        profiles.remove(id); saveIfEnabled(); changed();
    }

    public synchronized Optional<IdentityProfile> inferOwner(HttpRequest request) {
        List<IdentityProfile> matches = profiles.values().stream().filter(profile -> profile.matches(request)).toList();
        return matches.size() == 1 ? Optional.of(matches.get(0)) : Optional.empty();
    }

    public synchronized boolean persistenceEnabled() { return persistenceEnabled; }
    public synchronized void persistenceEnabled(boolean enabled) {
        persistenceEnabled = enabled; store.saveSetting("persistProfiles", Boolean.toString(enabled));
        if (enabled) store.saveProfiles(profiles.values()); else store.clearProfiles();
        changed();
    }

    public void addListener(Runnable listener) { listeners.add(listener); }
    private void saveIfEnabled() { if (persistenceEnabled) store.saveProfiles(profiles.values()); }
    private void changed() { listeners.forEach(Runnable::run); }
}
