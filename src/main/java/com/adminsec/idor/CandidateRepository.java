package com.adminsec.idor;

import com.adminsec.idor.model.Candidate;

import javax.swing.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public final class CandidateRepository {
    private volatile int maxCandidates = 5_000;
    private final Map<String, Candidate> candidates = new LinkedHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public synchronized void upsert(Candidate candidate) {
        upsert(candidate, true);
    }

    public synchronized void upsert(Candidate candidate, boolean notify) {
        Candidate old = candidates.get(candidate.key());
        if (old == null) candidates.put(candidate.key(), candidate);
        else old.updateMessage(candidate.message(), candidate.assessment());
        while (candidates.size() > maxCandidates) candidates.remove(candidates.keySet().iterator().next());
        if (notify) notifyListeners();
    }

    public synchronized List<Candidate> all() { return new ArrayList<>(candidates.values()); }
    public void addListener(Runnable listener) { listeners.add(listener); }
    public synchronized void setMaxCandidates(int value) { maxCandidates = Math.max(100, Math.min(value, 50_000)); }
    public void changed() { notifyListeners(); }
    private void notifyListeners() { SwingUtilities.invokeLater(() -> listeners.forEach(Runnable::run)); }
}
