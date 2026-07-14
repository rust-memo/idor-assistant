package com.adminsec.idor;

import com.adminsec.idor.model.Candidate;

import javax.swing.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/** Bounded candidate catalog retaining multiple observations per endpoint/reference. */
public final class CandidateCatalog {
    private volatile int maxCandidates = 5_000;
    private final Map<String, Candidate> candidates = new LinkedHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public synchronized void upsert(Candidate candidate) { upsert(candidate, true); }

    public synchronized void upsert(Candidate candidate, boolean notify) {
        Candidate existing = candidates.get(candidate.key());
        if (existing == null) candidates.put(candidate.key(), candidate);
        else {
            existing.updateMessage(candidate.message(), candidate.assessment());
            candidate.observations().forEach(observation -> existing.addObservation(
                    observation.message(), observation.assessment(), observation.ownerProfileId()));
        }
        while (candidates.size() > maxCandidates) candidates.remove(candidates.keySet().iterator().next());
        if (notify) notifyListeners();
    }

    public synchronized List<Candidate> all() { return new ArrayList<>(candidates.values()); }
    public synchronized Optional<Candidate> find(String key) { return Optional.ofNullable(candidates.get(key)); }
    public synchronized void assignOwner(IdentityProfile profile) {
        for (Candidate candidate : candidates.values()) for (var observation : candidate.observations())
            if (profile.matches(observation.message().request())) candidate.assignOwner(observation.id(), profile.id());
        notifyListeners();
    }
    public void addListener(Runnable listener) { listeners.add(listener); }
    public synchronized void setMaxCandidates(int value) { maxCandidates = Math.max(100, Math.min(value, 50_000)); }
    public void changed() { notifyListeners(); }
    private void notifyListeners() { SwingUtilities.invokeLater(() -> listeners.forEach(Runnable::run)); }
}
