package com.adminsec.idor.model;

import burp.api.montoya.http.message.HttpRequestResponse;

public final class Candidate {
    private final String key;
    private volatile Assessment assessment;
    private volatile HttpRequestResponse message;
    private volatile String reviewStatus;
    private volatile String comparisonStatus;
    private volatile String comparisonDetail;
    private volatile HttpRequestResponse control;
    private volatile HttpRequestResponse cross;

    public Candidate(String key, Assessment assessment, HttpRequestResponse message, String reviewStatus) {
        this.key = key;
        this.assessment = assessment;
        this.message = message;
        this.reviewStatus = reviewStatus;
        this.comparisonStatus = "Not tested";
        this.comparisonDetail = "";
    }

    public String key() { return key; }
    public Assessment assessment() { return assessment; }
    public HttpRequestResponse message() { return message; }
    public void updateMessage(HttpRequestResponse value, Assessment latestAssessment) { message = value; assessment = latestAssessment; }
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
}
