package com.adminsec.idor;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.adminsec.idor.model.Reference;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;

import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;

/** Central redaction used by reports and manually-created Audit Issues. */
public final class RedactionService {
    private static final Set<String> SENSITIVE_HEADERS;
    static {
        Set<String> headers = new LinkedHashSet<>(IdentityProfile.AUTH_HEADERS); headers.add("set-cookie");
        SENSITIVE_HEADERS = Set.copyOf(headers);
    }
    private static final Pattern JSON_SECRET = Pattern.compile(
            "(?i)([\"'](?:password|passwd|secret|token|api[_-]?key|session|cookie|authorization|csrf|xsrf)[\"']\\s*:\\s*)[\"'][^\"']*[\"']");
    private static final Pattern FORM_SECRET = Pattern.compile(
            "(?i)((?:password|passwd|secret|token|api[_-]?key|session|csrf|xsrf)=)[^&\\s]*");
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}(?:\\.[A-Za-z0-9_-]{8,})?\\b");

    public HttpRequestResponse redact(HttpRequestResponse message) {
        return redact(message, List.of());
    }

    public HttpRequestResponse redact(HttpRequestResponse message, Collection<Reference> references) {
        if (message == null) return null;
        HttpRequest request = message.request();
        for (String header : SENSITIVE_HEADERS) request = request.withRemovedHeader(header);
        if (request.query() != null && !request.query().isBlank()) request = request.withPath(request.pathWithoutQuery());
        String path = request.pathWithoutQuery();
        for (Reference reference : references) if ("Request".equals(reference.source()) && !reference.value().isBlank())
            path = path.replaceAll("/" + Pattern.quote(reference.value()) + "(?=/|$)", "/object-" + fingerprint(reference.value()));
        request = request.withPath(path).withBody(redactReferences(request.bodyToString(), references));
        if (!message.hasResponse()) return httpRequestResponse(request, null);
        HttpResponse response = message.response();
        for (String header : SENSITIVE_HEADERS) response = response.withRemovedHeader(header);
        response = response.withBody(redactReferences(response.bodyToString(), references));
        return httpRequestResponse(request, response);
    }

    public String redactText(String value) {
        if (value == null || value.isBlank()) return value == null ? "" : value;
        String result = JSON_SECRET.matcher(value).replaceAll("$1\"<redacted>\"");
        result = FORM_SECRET.matcher(result).replaceAll("$1<redacted>");
        return JWT.matcher(result).replaceAll("<redacted-jwt>");
    }

    public String snippet(String value, int limit) {
        String redacted = redactText(value).replaceAll("\\s+", " ").trim();
        return redacted.length() <= limit ? redacted : redacted.substring(0, Math.max(0, limit - 3)) + "...";
    }

    public String snippet(String value, Collection<Reference> references, int limit) {
        String safe = redactReferences(value, references).replaceAll("\\s+", " ").trim();
        return safe.length() <= limit ? safe : safe.substring(0, Math.max(0, limit - 3)) + "...";
    }

    public String redactReferences(String value, Collection<Reference> references) {
        String safe = redactText(value);
        if (references == null) return safe;
        for (Reference reference : references) if (reference.value() != null && !reference.value().isBlank())
            safe = safe.replace(reference.value(), "object-" + fingerprint(reference.value()));
        return safe;
    }

    public String fingerprint(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 12);
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
