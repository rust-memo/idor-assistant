package com.adminsec.idor;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public record IdentityProfile(String name, Map<String, String> headers, String fingerprint) {
    private static final Set<String> AUTH_HEADERS = Set.of(
            "authorization", "cookie", "proxy-authorization", "x-api-key", "api-key",
            "x-auth-token", "x-access-token", "x-session-token", "x-jwt-token",
            "x-user-id", "x-account-id", "x-customer-id", "x-member-id", "x-tenant-id",
            "x-organization-id", "x-org-id", "x-owner-id", "x-profile-id", "x-client-id"
    );

    public static IdentityProfile capture(String name, HttpRequest request) {
        Map<String, String> captured = new LinkedHashMap<>();
        for (HttpHeader header : request.headers()) {
            if (AUTH_HEADERS.contains(header.name().toLowerCase(Locale.ROOT))) captured.put(header.name(), header.value());
        }
        return new IdentityProfile(name, Collections.unmodifiableMap(captured), fingerprint(captured));
    }

    public static IdentityProfile fromHeaders(String name, Map<String, String> headers) {
        Map<String, String> copy = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        return new IdentityProfile(name, copy, fingerprint(copy));
    }

    public HttpRequest apply(HttpRequest request) {
        HttpRequest result = withoutAuthentication(request);
        for (Map.Entry<String, String> header : headers.entrySet()) result = result.withAddedHeader(header.getKey(), header.getValue());
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

    public String display() { return headers.isEmpty() ? name + " [not captured]" : name + " [" + fingerprint.substring(0, Math.min(10, fingerprint.length())) + "]"; }

    static String fingerprint(Map<String, String> headers) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            headers.entrySet().stream().sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                    .forEach(e -> digest.update((e.getKey().toLowerCase(Locale.ROOT) + ":" + e.getValue() + "\n").getBytes(StandardCharsets.UTF_8)));
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
