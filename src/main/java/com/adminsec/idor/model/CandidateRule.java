package com.adminsec.idor.model;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

/** A metadata-only, scoped user decision. Raw identifiers and HTTP data are never stored. */
public record CandidateRule(String id, Action action, Scope scope, String host, String method,
                            String endpointTemplate, String referenceName, String location,
                            String structuralPath, String reason, String createdAt) {
    public enum Action { IGNORE, ALLOW }
    public enum Scope { ENDPOINT, HOST }

    public CandidateRule {
        id = blank(id) ? UUID.randomUUID().toString() : id;
        action = action == null ? Action.IGNORE : action;
        scope = scope == null ? Scope.ENDPOINT : scope;
        host = clean(host);
        method = clean(method).toUpperCase(Locale.ROOT);
        endpointTemplate = clean(endpointTemplate);
        referenceName = normalize(referenceName);
        location = clean(location).toLowerCase(Locale.ROOT);
        structuralPath = clean(structuralPath);
        reason = blank(reason) ? "User-marked false positive" : reason.trim();
        createdAt = blank(createdAt) ? Instant.now().toString() : createdAt;
    }

    public static CandidateRule create(Action action, Scope scope, String host, String method,
                                       String endpointTemplate, Reference reference, String reason) {
        return new CandidateRule("", action, scope, host, method, endpointTemplate, reference.name(),
                reference.location(), reference.structuralPath(), reason, "");
    }

    public boolean matches(String candidateHost, String candidateMethod, String candidateEndpoint, Reference reference) {
        if (!host.equalsIgnoreCase(clean(candidateHost))) return false;
        if (!referenceName.equals(normalize(reference.name()))) return false;
        if (!location.isBlank() && !location.equals(clean(reference.location()).toLowerCase(Locale.ROOT))) return false;
        if (!structuralPath.isBlank() && !structuralPath.equals(reference.structuralPath())) return false;
        return scope == Scope.HOST || (method.equalsIgnoreCase(clean(candidateMethod))
                && endpointTemplate.equals(clean(candidateEndpoint)));
    }

    public String display() {
        String target = scope == Scope.HOST ? host : method + " " + host + endpointTemplate;
        return action + " | " + target + " | " + referenceName + "@" + location
                + (structuralPath.isBlank() ? "" : ":" + structuralPath);
    }

    private static String normalize(String value) {
        return clean(value).replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT)
                .replace('-', '_').replace('.', '_').replaceAll("\\[[^]]*]", "_")
                .replaceAll("_+", "_").replaceAll("^_|_$", "");
    }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
    private static String clean(String value) { return value == null ? "" : value.trim(); }
}
