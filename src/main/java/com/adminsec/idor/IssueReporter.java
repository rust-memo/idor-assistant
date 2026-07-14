package com.adminsec.idor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.*;
import com.adminsec.idor.model.Candidate;

import java.util.*;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

/** Adds a redacted Site Map issue only after an explicit UI confirmation. */
public final class IssueReporter {
    private final MontoyaApi api;
    private final RedactionService redaction;

    public IssueReporter(MontoyaApi api, RedactionService redaction) {
        this.api = Objects.requireNonNull(api); this.redaction = Objects.requireNonNull(redaction);
    }

    public void report(Candidate candidate, AuditIssueSeverity severity) {
        if (candidate == null || !candidate.comparisonStatus().toLowerCase(Locale.ROOT).contains("suspicious"))
            throw new IllegalStateException("Only reviewed suspicious comparisons can be reported");
        if (candidate.control() == null || candidate.cross() == null)
            throw new IllegalStateException("Owner and cross-account evidence are required");
        List<HttpRequestResponse> evidence = new ArrayList<>();
        evidence.add(redaction.redact(candidate.control(), candidate.assessment().references()));
        evidence.add(redaction.redact(candidate.cross(), candidate.assessment().references()));
        String baseUrl = stripQuery(candidate.message().request().url());
        String detail = "The selected object was requested with a different captured identity and returned a suspicious successful response. "
                + html(candidate.comparisonDetail()) + "<br><br>This issue was added only after manual review. Confirm ownership and impact before reporting it.";
        AuditIssue issue = auditIssue("Potential IDOR/BOLA", detail,
                "Enforce server-side authorization for every object access using the authenticated principal and the requested action.",
                baseUrl, severity, AuditIssueConfidence.FIRM,
                "Insecure direct object references occur when an application accepts an object identifier without enforcing object-level authorization.",
                "Use deny-by-default object authorization checks and test them across roles and tenants.",
                AuditIssueSeverity.HIGH, evidence);
        api.siteMap().add(issue);
    }

    private String stripQuery(String value) { int index = value.indexOf('?'); return index < 0 ? value : value.substring(0, index); }
    private String html(String value) { return (value == null ? "" : value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"); }
}
