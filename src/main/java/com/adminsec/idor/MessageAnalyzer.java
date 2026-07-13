package com.adminsec.idor;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.adminsec.idor.model.*;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

public final class MessageAnalyzer {
    private final DetectionEngine engine;
    private final ProjectStore projectStore;

    public MessageAnalyzer(DetectionEngine engine, ProjectStore projectStore) {
        this.engine = engine; this.projectStore = projectStore;
    }

    public Optional<Candidate> analyze(HttpRequestResponse message) {
        var request = message.request();
        Map<String, String> headers = request.headers().stream().collect(Collectors.toMap(
                HttpHeader::name, HttpHeader::value, (a, b) -> b, LinkedHashMap::new));
        List<Reference> parameters = new ArrayList<>();
        for (ParsedHttpParameter p : request.parameters()) {
            if (!"COOKIE".equals(p.type().name())) parameters.add(new Reference(p.name(), p.value(), p.type().name(), ""));
        }
        int status = message.hasResponse() ? message.response().statusCode() : 0;
        var input = new DetectionEngine.Input(request.method(), request.url(), request.pathWithoutQuery(), headers,
                parameters, request.bodyToString(), message.hasResponse() ? message.response().bodyToString() : "", status);
        Optional<Assessment> assessment = engine.analyze(input);
        if (assessment.isEmpty()) return Optional.empty();
        String host;
        try { host = URI.create(request.url()).getHost(); } catch (Exception e) { host = request.httpService().host(); }
        String names = assessment.get().references().stream().filter(r -> "Request".equals(r.source()))
                .map(Reference::name).map(String::toLowerCase).distinct().sorted().collect(Collectors.joining(","));
        String key = request.method() + " " + host + " " + assessment.get().endpointTemplate() + " " + names;
        decorate(message, assessment.get());
        Candidate candidate = new Candidate(key, assessment.get(), message, projectStore.loadReviewStatus(key));
        String[] comparison = projectStore.loadComparison(key);
        candidate.restoreComparison(comparison[0], comparison[1]);
        return Optional.of(candidate);
    }

    private void decorate(HttpRequestResponse message, Assessment assessment) {
        if (message.annotations() == null) return;
        HighlightColor color = assessment.score() >= 75 ? HighlightColor.RED : assessment.score() >= 55 ? HighlightColor.ORANGE : HighlightColor.YELLOW;
        if (!message.annotations().hasHighlightColor() || message.annotations().highlightColor() == HighlightColor.NONE)
            message.annotations().setHighlightColor(color);
        String note = "[IDOR Assistant] " + assessment.priority() + " (" + assessment.score() + "): " +
                assessment.references().stream().limit(3).map(r -> r.name() + "=" + truncate(r.value())).collect(Collectors.joining(", "));
        String old = message.annotations().notes();
        if (old == null || !old.contains(note)) message.annotations().setNotes((old == null || old.isBlank() ? "" : old + " | ") + note);
    }

    private String truncate(String value) { return value.length() <= 60 ? value : value.substring(0, 57) + "..."; }
}
