package com.adminsec.idor.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.Instant;
import java.util.*;

public final class Candidate {
    private final String key;
    private volatile Assessment assessment;
    private volatile HttpRequestResponse message;
    private volatile String reviewStatus;
    private volatile String comparisonStatus;
    private volatile String comparisonDetail;
    private volatile HttpRequestResponse control;
    private volatile HttpRequestResponse cross;
    private final Deque<ObjectObservation> observations = new ArrayDeque<>();
    private static final int MAX_OBSERVATIONS = 20;

    public Candidate(String key, Assessment assessment, HttpRequestResponse message, String reviewStatus) {
        this(key, assessment, message, reviewStatus, "");
    }

    public Candidate(String key, Assessment assessment, HttpRequestResponse message, String reviewStatus,
                     String ownerProfileId) {
        this.key = key;
        this.assessment = assessment;
        this.message = message;
        this.reviewStatus = reviewStatus;
        this.comparisonStatus = "Not tested";
        this.comparisonDetail = "";
        addObservation(message, assessment, ownerProfileId);
    }

    public String key() { return key; }
    public Assessment assessment() { return assessment; }
    public HttpRequestResponse message() { return message; }
    public synchronized void updateMessage(HttpRequestResponse value, Assessment latestAssessment) {
        message = value; assessment = latestAssessment; addObservation(value, latestAssessment, "");
    }
    public synchronized void reclassify(Assessment value) {
        if (value != null) assessment = value;
    }
    public synchronized void addObservation(HttpRequestResponse value, Assessment latestAssessment, String ownerProfileId) {
        if (value == null || latestAssessment == null) return;
        String observationId = Integer.toHexString(Objects.hash(value.request().method(), value.request().url(),
                value.hasResponse() ? value.response().statusCode() : 0, value.request().bodyToString()));
        List<String> fingerprints = latestAssessment.references().stream()
                .filter(r -> "Request".equals(r.source())).map(r -> fingerprint(r.value())).distinct().toList();
        if (observations.stream().anyMatch(existing -> existing.id().equals(observationId))) return;
        observations.addLast(new ObjectObservation(observationId, Instant.now(), ownerProfileId,
                latestAssessment, value, fingerprints));
        while (observations.size() > MAX_OBSERVATIONS) observations.removeFirst();
    }
    public synchronized List<ObjectObservation> observations() { return List.copyOf(observations); }
    public synchronized void assignOwner(String observationId, String profileId) {
        List<ObjectObservation> updated = observations.stream().map(observation -> observation.id().equals(observationId)
                ? new ObjectObservation(observation.id(), observation.observedAt(), profileId, observation.assessment(),
                observation.message(), observation.referenceFingerprints()) : observation).toList();
        observations.clear(); observations.addAll(updated);
    }
    public String reviewStatus() { return reviewStatus; }
    public void reviewStatus(String value) { reviewStatus = value; }
    public String comparisonStatus() { return comparisonStatus; }
    public String comparisonDetail() { return comparisonDetail; }
    public HttpRequestResponse control() { return control; }
    public HttpRequestResponse cross() { return cross; }
    public void comparison(String status, String detail, HttpRequestResponse control, HttpRequestResponse cross) {
        this.comparisonStatus = status;
        this.comparisonDetail = detail;
        this.control = control;
        this.cross = cross;
    }
    public void restoreComparison(String status, String detail) {
        this.comparisonStatus = status;
        this.comparisonDetail = detail;
    }

    private static String fingerprint(String value) {
        try {
            byte[] bytes = java.security.MessageDigest.getInstance("SHA-256")
                    .digest((value == null ? "" : value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(bytes).substring(0, 12);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
