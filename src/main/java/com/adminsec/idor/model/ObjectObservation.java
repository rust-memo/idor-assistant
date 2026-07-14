package com.adminsec.idor.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.Instant;
import java.util.List;

/** One observed request/response sample. Raw HTTP remains memory-only. */
public record ObjectObservation(String id, Instant observedAt, String ownerProfileId,
                                Assessment assessment, HttpRequestResponse message,
                                List<String> referenceFingerprints) {
    public ObjectObservation {
        id = id == null ? "" : id;
        observedAt = observedAt == null ? Instant.now() : observedAt;
        ownerProfileId = ownerProfileId == null ? "" : ownerProfileId;
        referenceFingerprints = referenceFingerprints == null ? List.of() : List.copyOf(referenceFingerprints);
    }
}
