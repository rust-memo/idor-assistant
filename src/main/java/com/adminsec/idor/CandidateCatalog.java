package com.adminsec.idor;

import com.adminsec.idor.model.*;

import javax.swing.*;
import java.net.URI;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/** Bounded active/suppressed catalogs retaining multiple observations per endpoint/reference. */
public final class CandidateCatalog {
    private volatile int maxCandidates = 5_000;
    private final Map<String, Candidate> active = new LinkedHashMap<>();
    private final Map<String, Candidate> suppressed = new LinkedHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public synchronized void upsert(Candidate candidate) { upsert(candidate, true); }

    public synchronized void upsert(Candidate candidate, boolean notify) {
        Candidate existing = active.remove(candidate.key());
        if (existing == null) existing = suppressed.remove(candidate.key());
        Candidate merged = existing == null ? candidate : merge(existing, candidate);
        promoteRepeatedEvidence(merged);
        destination(merged).put(merged.key(), merged);
        trim(active); trim(suppressed);
        if (notify) notifyListeners();
    }

    private Candidate merge(Candidate existing, Candidate incoming) {
        Assessment previous = existing.assessment();
        existing.updateMessage(incoming.message(), incoming.assessment());
        if (previous.disposition() == CandidateDisposition.ACTIVE
                && incoming.assessment().disposition() == CandidateDisposition.SUPPRESSED) existing.reclassify(previous);
        incoming.observations().forEach(observation -> existing.addObservation(
                observation.message(), observation.assessment(), observation.ownerProfileId()));
        return existing;
    }

    private void promoteRepeatedEvidence(Candidate candidate) {
        Assessment current = candidate.assessment();
        if (current.disposition() != CandidateDisposition.SUPPRESSED || current.score() < 40) return;
        long distinct = candidate.observations().stream().flatMap(value -> value.referenceFingerprints().stream()).distinct().count();
        if (distinct < 2) return;
        int promotedScore = Math.min(100, current.score() + 15);
        if (promotedScore < 55) return;
        List<String> reasons = new ArrayList<>(current.reasons());
        reasons.add("repeated endpoint with distinct observed identifiers");
        candidate.reclassify(new Assessment(promotedScore, promotedScore >= 75 ? "High" : "Medium",
                current.endpointTemplate(), current.references(), reasons, CandidateDisposition.ACTIVE, ""));
    }

    public synchronized void suppress(Candidate candidate, String reason) {
        Candidate found = active.remove(candidate.key());
        if (found == null) found = suppressed.get(candidate.key());
        if (found == null) return;
        Assessment old = found.assessment();
        found.reclassify(new Assessment(old.score(), old.priority(), old.endpointTemplate(), old.references(), old.reasons(),
                CandidateDisposition.SUPPRESSED, reason == null ? "User-marked false positive" : reason));
        suppressed.put(found.key(), found);
        notifyListeners();
    }

    public synchronized void restore(Candidate candidate) {
        Candidate found = suppressed.remove(candidate.key());
        if (found == null) return;
        Assessment old = found.assessment();
        int score = Math.max(55, old.score());
        found.reclassify(new Assessment(score, score >= 75 ? "High" : "Medium", old.endpointTemplate(),
                old.references(), old.reasons(), CandidateDisposition.ACTIVE, ""));
        active.put(found.key(), found);
        trim(active);
        notifyListeners();
    }

    public synchronized void applyIgnoreRule(CandidateRule rule) {
        List<Candidate> matches = active.values().stream().filter(candidate -> matches(rule, candidate)).toList();
        for (Candidate candidate : matches) suppressWithoutNotify(candidate, rule.reason());
        notifyListeners();
    }

    private void suppressWithoutNotify(Candidate candidate, String reason) {
        Candidate found = active.remove(candidate.key());
        if (found == null) return;
        Assessment old = found.assessment();
        found.reclassify(new Assessment(old.score(), old.priority(), old.endpointTemplate(), old.references(), old.reasons(),
                CandidateDisposition.SUPPRESSED, reason));
        suppressed.put(found.key(), found);
    }

    private boolean matches(CandidateRule rule, Candidate candidate) {
        String host;
        try { host = Optional.ofNullable(URI.create(candidate.message().request().url()).getHost()).orElse(""); }
        catch (Exception ignored) { host = ""; }
        String method = candidate.message().request().method();
        String endpoint = candidate.assessment().endpointTemplate();
        String finalHost = host;
        return candidate.assessment().references().stream().filter(ref -> "Request".equals(ref.source()))
                .anyMatch(ref -> rule.matches(finalHost, method, endpoint, ref));
    }

    private Map<String, Candidate> destination(Candidate candidate) {
        return candidate.assessment().disposition() == CandidateDisposition.ACTIVE ? active : suppressed;
    }

    private void trim(Map<String, Candidate> values) {
        while (values.size() > maxCandidates) values.remove(values.keySet().iterator().next());
    }

    public synchronized List<Candidate> all() { return new ArrayList<>(active.values()); }
    public synchronized List<Candidate> suppressed() { return new ArrayList<>(suppressed.values()); }
    public synchronized Optional<Candidate> find(String key) {
        Candidate found = active.get(key);
        return Optional.ofNullable(found == null ? suppressed.get(key) : found);
    }
    public synchronized void assignOwner(IdentityProfile profile) {
        for (Candidate candidate : combined()) for (var observation : candidate.observations())
            if (profile.matches(observation.message().request())) candidate.assignOwner(observation.id(), profile.id());
        notifyListeners();
    }
    private List<Candidate> combined() {
        List<Candidate> result = new ArrayList<>(active.values()); result.addAll(suppressed.values()); return result;
    }
    public void addListener(Runnable listener) { listeners.add(listener); }
    public synchronized void setMaxCandidates(int value) {
        maxCandidates = Math.max(100, Math.min(value, 50_000)); trim(active); trim(suppressed);
    }
    public void changed() { notifyListeners(); }
    private void notifyListeners() { SwingUtilities.invokeLater(() -> listeners.forEach(Runnable::run)); }
}
