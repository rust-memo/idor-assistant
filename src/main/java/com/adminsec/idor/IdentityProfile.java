package com.adminsec.idor;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public record IdentityProfile(String id, String name, String role, Map<String, String> headers,
                              List<SessionSubstitution> substitutions, String fingerprint) {
    static final Set<String> AUTH_HEADERS = Set.of(
            "authorization", "cookie", "proxy-authorization", "x-api-key", "api-key",
            "x-auth-token", "x-access-token", "x-session-token", "x-jwt-token",
            "x-user-id", "x-account-id", "x-customer-id", "x-member-id", "x-tenant-id",
            "x-organization-id", "x-org-id", "x-owner-id", "x-profile-id", "x-client-id",
            "x-csrf-token", "x-xsrf-token", "x-request-verification-token"
    );
    private static final Set<String> SESSION_PARAMETER_NAMES = Set.of(
            "csrf", "csrf_token", "csrftoken", "xsrf", "xsrf_token", "_token",
            "authenticity_token", "requestverificationtoken", "__requestverificationtoken"
    );

    public IdentityProfile {
        id = id == null || id.isBlank() ? UUID.randomUUID().toString() : id;
        name = name == null || name.isBlank() ? "Profile" : name.trim();
        role = role == null ? "" : role.trim();
        headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers == null ? Map.of() : headers));
        substitutions = List.copyOf(substitutions == null ? List.of() : substitutions);
        fingerprint = fingerprint == null || fingerprint.isBlank() ? fingerprint(headers, substitutions) : fingerprint;
    }

    /** Compatibility constructor for v2 callers and stored profiles. */
    public IdentityProfile(String name, Map<String, String> headers, String fingerprint) {
        this(UUID.randomUUID().toString(), name, "", headers, List.of(), fingerprint);
    }

    public static IdentityProfile capture(String name, HttpRequest request) {
        Map<String, String> captured = new LinkedHashMap<>();
        for (HttpHeader header : request.headers()) {
            if (AUTH_HEADERS.contains(header.name().toLowerCase(Locale.ROOT))) captured.put(header.name(), header.value());
        }
        List<SessionSubstitution> substitutions = new ArrayList<>();
        request.parameters().stream()
                .filter(parameter -> SESSION_PARAMETER_NAMES.contains(normalize(parameter.name())))
                .forEach(parameter -> substitutions.add(SessionSubstitution.from(
                        parameter.type().name(), parameter.name(), parameter.value())));
        return create(name, "", captured, substitutions);
    }

    public static IdentityProfile fromHeaders(String name, Map<String, String> headers) {
        return create(name, "", headers, List.of());
    }

    public static IdentityProfile create(String name, String role, Map<String, String> headers,
                                         Collection<SessionSubstitution> substitutions) {
        Map<String, String> copy = new LinkedHashMap<>(headers == null ? Map.of() : headers);
        List<SessionSubstitution> session = List.copyOf(substitutions == null ? List.of() : substitutions);
        return new IdentityProfile(UUID.randomUUID().toString(), name, role, copy, session, fingerprint(copy, session));
    }

    public HttpRequest apply(HttpRequest request) {
        HttpRequest result = withoutAuthentication(request);
        for (Map.Entry<String, String> header : headers.entrySet()) result = result.withAddedHeader(header.getKey(), header.getValue());
        for (SessionSubstitution substitution : substitutions) {
            try {
                if (result.hasParameter(substitution.name(), substitution.parameterType()))
                    result = result.withUpdatedParameters(HttpParameter.parameter(
                            substitution.name(), substitution.value(), substitution.parameterType()));
            } catch (IllegalArgumentException ignored) { }
        }
        return result;
    }

    public static HttpRequest withoutAuthentication(HttpRequest request) {
        HttpRequest result = request;
        Set<String> remove = new LinkedHashSet<>(AUTH_HEADERS);
        for (HttpHeader header : request.headers()) {
            if (remove.contains(header.name().toLowerCase(Locale.ROOT))) result = result.withRemovedHeader(header.name());
        }
        return result;
    }

    public boolean sameIdentity(IdentityProfile other) {
        return other != null && !headers.isEmpty() && fingerprint.equals(other.fingerprint);
    }

    public boolean matches(HttpRequest request) {
        if (request == null || headers.isEmpty()) return false;
        for (Map.Entry<String, String> header : headers.entrySet())
            if (!Objects.equals(header.getValue(), request.headerValue(header.getKey()))) return false;
        return true;
    }

    public String display() {
        String label = role.isBlank() ? name : name + " (" + role + ")";
        return headers.isEmpty() ? label + " [not captured]" : label + " [" + fingerprint.substring(0, Math.min(10, fingerprint.length())) + "]";
    }

    static String fingerprint(Map<String, String> headers) {
        return fingerprint(headers, List.of());
    }

    static String fingerprint(Map<String, String> headers, Collection<SessionSubstitution> substitutions) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            headers.entrySet().stream().sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                    .forEach(e -> digest.update((e.getKey().toLowerCase(Locale.ROOT) + ":" + e.getValue() + "\n").getBytes(StandardCharsets.UTF_8)));
            substitutions.stream().sorted(Comparator.comparing(s -> s.location().name() + ":" + s.name()))
                    .forEach(s -> digest.update((s.location() + ":" + normalize(s.name()) + ":" + s.value() + "\n").getBytes(StandardCharsets.UTF_8)));
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static String normalize(String raw) {
        return raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT).replace('-', '_');
    }
}
