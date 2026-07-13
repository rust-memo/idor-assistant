package com.adminsec.idor;

import burp.api.montoya.persistence.PersistedObject;

import java.nio.charset.StandardCharsets;
import java.util.*;

public final class ProjectStore {
    private final PersistedObject data;

    public ProjectStore(PersistedObject data) { this.data = data; }

    public void saveProfile(IdentityProfile profile) {
        saveProfile(profile.name(), profile);
    }

    public void saveProfile(String slot, IdentityProfile profile) {
        StringBuilder encoded = new StringBuilder();
        Base64.Encoder b64 = Base64.getEncoder();
        profile.headers().forEach((name, value) -> encoded.append(b64.encodeToString(name.getBytes(StandardCharsets.UTF_8)))
                .append(':').append(b64.encodeToString(value.getBytes(StandardCharsets.UTF_8))).append('\n'));
        data.setString("profile." + slot, encoded.toString());
        data.setString("profileName." + slot, profile.name());
    }

    public IdentityProfile loadProfile(String name) {
        String raw = data.getString("profile." + name);
        String displayName = data.getString("profileName." + name);
        if (displayName == null || displayName.isBlank()) displayName = name;
        if (raw == null) return new IdentityProfile(displayName, Map.of(), IdentityProfile.fingerprint(Map.of()));
        Map<String, String> headers = new LinkedHashMap<>();
        Base64.Decoder b64 = Base64.getDecoder();
        for (String line : raw.split("\\n")) {
            String[] pair = line.split(":", 2);
            try { if (pair.length == 2) headers.put(new String(b64.decode(pair[0]), StandardCharsets.UTF_8), new String(b64.decode(pair[1]), StandardCharsets.UTF_8)); }
            catch (IllegalArgumentException ignored) { }
        }
        return new IdentityProfile(displayName, Collections.unmodifiableMap(headers), IdentityProfile.fingerprint(headers));
    }

    public void clearProfile(String slot) { data.deleteString("profile." + slot); data.deleteString("profileName." + slot); }

    public void saveReviewed(String candidateKey, boolean reviewed) { saveReviewStatus(candidateKey, reviewed ? "Reviewed" : "New"); }
    public boolean isReviewed(String candidateKey) { return !"New".equals(loadReviewStatus(candidateKey)); }
    public void saveReviewStatus(String candidateKey, String status) { data.setString("reviewStatus." + safeKey(candidateKey), status); }
    public String loadReviewStatus(String candidateKey) {
        String status = data.getString("reviewStatus." + safeKey(candidateKey));
        if (status != null && !status.isBlank()) return status;
        return Boolean.TRUE.equals(data.getBoolean("reviewed." + Integer.toHexString(candidateKey.hashCode()))) ? "Reviewed" : "New";
    }
    public void saveComparison(String candidateKey, String status, String detail) {
        Base64.Encoder b64 = Base64.getEncoder();
        data.setString("comparison." + safeKey(candidateKey), b64.encodeToString(status.getBytes(StandardCharsets.UTF_8)) + ":"
                + b64.encodeToString(detail.getBytes(StandardCharsets.UTF_8)));
    }
    public String[] loadComparison(String candidateKey) {
        String raw = data.getString("comparison." + safeKey(candidateKey));
        if (raw == null) return new String[]{"Not tested", ""};
        try { String[] pair = raw.split(":", 2); Base64.Decoder b64 = Base64.getDecoder();
            return pair.length == 2 ? new String[]{new String(b64.decode(pair[0]), StandardCharsets.UTF_8), new String(b64.decode(pair[1]), StandardCharsets.UTF_8)} : new String[]{"Not tested", ""};
        } catch (IllegalArgumentException e) { return new String[]{"Not tested", ""}; }
    }
    public void saveSetting(String key, String value) { data.setString("setting." + key, value == null ? "" : value); }
    public String loadSetting(String key) { String value = data.getString("setting." + key); return value == null ? "" : value; }
    private String safeKey(String value) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
}
