package com.adminsec.idor.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

/** Structured evidence produced by a controlled identity comparison. */
public record ComparisonEvidence(String status, String detail, double similarity,
                                 double baselineStability, boolean ownershipEvidence,
                                 List<String> indicators, String confidence,
                                 HttpRequestResponse ownerControl, HttpRequestResponse crossAccount) {
    public ComparisonEvidence {
        status = status == null ? "Inconclusive" : status;
        detail = detail == null ? "" : detail;
        indicators = indicators == null ? List.of() : List.copyOf(indicators);
        confidence = confidence == null ? "Low" : confidence;
    }
}
