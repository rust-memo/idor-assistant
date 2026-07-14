package com.adminsec.idor;

import com.google.gson.*;
import com.adminsec.idor.model.Candidate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Metadata-only reports: never exports request/response bodies or authentication. */
public final class ReportExporter {
    private final RedactionService redaction = new RedactionService();

    public void export(Path path, List<Candidate> candidates) throws IOException {
        export(path, candidates, false);
    }

    public void export(Path path, List<Candidate> candidates, boolean includeRedactedEvidence) throws IOException {
        String lower = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (lower.endsWith(".json")) exportJson(path, candidates, includeRedactedEvidence);
        else if (lower.endsWith(".html") || lower.endsWith(".htm")) exportHtml(path, candidates, includeRedactedEvidence);
        else new CsvExporter().export(path, candidates);
    }

    private void exportJson(Path path, List<Candidate> candidates, boolean includeEvidence) throws IOException {
        JsonArray rows = new JsonArray();
        for (Candidate c : candidates) rows.add(asJson(c, includeEvidence));
        JsonObject root = new JsonObject(); root.addProperty("report", "IDOR/BOLA Assistant"); root.add("candidates", rows);
        Files.writeString(path, new GsonBuilder().setPrettyPrinting().create().toJson(root), StandardCharsets.UTF_8);
    }

    private JsonObject asJson(Candidate c, boolean includeEvidence) {
        JsonObject row = new JsonObject();
        row.addProperty("score", c.assessment().score()); row.addProperty("priority", c.assessment().priority());
        row.addProperty("method", c.message().request().method()); row.addProperty("url", stripQuery(c.message().request().url()));
        row.addProperty("endpoint", c.assessment().endpointTemplate()); row.addProperty("review", c.reviewStatus());
        row.addProperty("comparison", c.comparisonStatus()); row.addProperty("comparisonDetail", c.comparisonDetail());
        JsonArray refs = new JsonArray();
        c.assessment().references().forEach(r -> { JsonObject ref = new JsonObject(); ref.addProperty("name", r.name());
            ref.addProperty("location", r.location()); ref.addProperty("source", r.source());
            ref.addProperty("path", r.structuralPath()); ref.addProperty("sensitivity", r.sensitivity()); refs.add(ref); });
        row.add("references", refs); row.addProperty("observations", c.observations().size());
        if (includeEvidence) {
            JsonObject evidence = new JsonObject();
            if (c.control() != null && c.control().hasResponse()) evidence.addProperty("ownerSnippet", redaction.snippet(c.control().response().bodyToString(), c.assessment().references(), 1_000));
            if (c.cross() != null && c.cross().hasResponse()) evidence.addProperty("crossAccountSnippet", redaction.snippet(c.cross().response().bodyToString(), c.assessment().references(), 1_000));
            row.add("redactedEvidence", evidence);
        }
        return row;
    }

    private void exportHtml(Path path, List<Candidate> candidates, boolean includeEvidence) throws IOException {
        StringBuilder html = new StringBuilder("<!doctype html><meta charset=\"utf-8\"><title>IDOR/BOLA report</title>"
                + "<style>body{font:14px sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.45rem;text-align:left}th{background:#eee}</style>"
                + "<h1>IDOR/BOLA Assistant report</h1><p>" + (includeEvidence
                ? "Optional evidence snippets are redacted; authentication and query values are excluded."
                : "Metadata-only export; authentication, query values and message bodies are excluded.") + "</p>"
                + "<table><thead><tr><th>Score</th><th>Priority</th><th>Method</th><th>URL</th><th>Endpoint</th><th>Review</th><th>Comparison</th><th>Detail</th></tr></thead><tbody>");
        for (Candidate c : candidates) html.append("<tr><td>").append(c.assessment().score()).append("</td><td>")
                .append(escape(c.assessment().priority())).append("</td><td>").append(escape(c.message().request().method()))
                .append("</td><td>").append(escape(stripQuery(c.message().request().url()))).append("</td><td>")
                .append(escape(c.assessment().endpointTemplate())).append("</td><td>").append(escape(c.reviewStatus()))
                .append("</td><td>").append(escape(c.comparisonStatus())).append("</td><td>")
                .append(escape(c.comparisonDetail())).append("</td></tr>");
        if (includeEvidence) for (Candidate c : candidates) {
            if (c.control() == null || c.cross() == null || !c.control().hasResponse() || !c.cross().hasResponse()) continue;
            html.append("<tr><td colspan=\"8\"><strong>Redacted evidence for ").append(escape(c.assessment().endpointTemplate()))
                    .append("</strong><br>Owner: <code>").append(escape(redaction.snippet(c.control().response().bodyToString(), c.assessment().references(), 800)))
                    .append("</code><br>Other: <code>").append(escape(redaction.snippet(c.cross().response().bodyToString(), c.assessment().references(), 800)))
                    .append("</code></td></tr>");
        }
        Files.writeString(path, html.append("</tbody></table>").toString(), StandardCharsets.UTF_8);
    }

    private String stripQuery(String url) { int q = url.indexOf('?'); return q < 0 ? url : url.substring(0, q); }
    private String escape(String value) { return (value == null ? "" : value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"); }
}
