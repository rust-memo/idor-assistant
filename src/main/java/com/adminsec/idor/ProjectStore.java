package com.adminsec.idor;

import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.*;
import com.adminsec.idor.model.CandidateRule;

import java.nio.charset.StandardCharsets;
import java.util.*;

public final class ProjectStore {
    public static final int SCHEMA_VERSION = 4;
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

    public void saveProfiles(Collection<IdentityProfile> profiles) {
        Base64.Encoder b64 = Base64.getEncoder();
        JsonArray rows = new JsonArray();
        for (IdentityProfile profile : profiles) {
            JsonObject row = new JsonObject();
            row.addProperty("id", profile.id()); row.addProperty("name", profile.name()); row.addProperty("role", profile.role());
            JsonArray headers = new JsonArray();
            profile.headers().forEach((name, value) -> {
                JsonObject header = new JsonObject();
                header.addProperty("name", b64.encodeToString(name.getBytes(StandardCharsets.UTF_8)));
                header.addProperty("value", b64.encodeToString(value.getBytes(StandardCharsets.UTF_8)));
                headers.add(header);
            });
            row.add("headers", headers);
            JsonArray substitutions = new JsonArray();
            profile.substitutions().forEach(value -> {
                JsonObject substitution = new JsonObject(); substitution.addProperty("location", value.location().name());
                substitution.addProperty("name", b64.encodeToString(value.name().getBytes(StandardCharsets.UTF_8)));
                substitution.addProperty("value", b64.encodeToString(value.value().getBytes(StandardCharsets.UTF_8)));
                substitutions.add(substitution);
            });
            row.add("substitutions", substitutions); rows.add(row);
        }
        data.setString("v3.profiles", rows.toString());
        data.setString("schemaVersion", Integer.toString(SCHEMA_VERSION));
    }

    public List<IdentityProfile> loadProfiles() {
        String raw = data.getString("v3.profiles");
        if (raw == null || raw.isBlank()) return migrateLegacyProfiles();
        List<IdentityProfile> result = new ArrayList<>();
        Base64.Decoder b64 = Base64.getDecoder();
        try {
            for (JsonElement element : JsonParser.parseString(raw).getAsJsonArray()) {
                JsonObject row = element.getAsJsonObject(); Map<String, String> headers = new LinkedHashMap<>();
                for (JsonElement value : row.getAsJsonArray("headers")) {
                    JsonObject header = value.getAsJsonObject(); headers.put(decode(b64, header.get("name")), decode(b64, header.get("value")));
                }
                List<SessionSubstitution> substitutions = new ArrayList<>();
                JsonArray stored = row.has("substitutions") ? row.getAsJsonArray("substitutions") : new JsonArray();
                for (JsonElement value : stored) {
                    JsonObject substitution = value.getAsJsonObject();
                    substitutions.add(SessionSubstitution.from(substitution.get("location").getAsString(),
                            decode(b64, substitution.get("name")), decode(b64, substitution.get("value"))));
                }
                String role = row.has("role") ? row.get("role").getAsString() : "";
                result.add(new IdentityProfile(row.get("id").getAsString(), row.get("name").getAsString(), role,
                        headers, substitutions, IdentityProfile.fingerprint(headers, substitutions)));
            }
        } catch (Exception ignored) { return List.of(); }
        return List.copyOf(result);
    }

    public void clearProfiles() { data.deleteString("v3.profiles"); clearProfile("A"); clearProfile("B"); }

    private List<IdentityProfile> migrateLegacyProfiles() {
        if (!Boolean.parseBoolean(loadSetting("persistProfiles"))) return List.of();
        List<IdentityProfile> migrated = new ArrayList<>();
        for (String slot : List.of("A", "B")) {
            IdentityProfile legacy = loadProfile(slot);
            if (!legacy.headers().isEmpty()) migrated.add(new IdentityProfile(UUID.randomUUID().toString(),
                    legacy.name(), "Legacy profile " + slot, legacy.headers(), List.of(), legacy.fingerprint()));
        }
        if (!migrated.isEmpty()) {
            saveProfiles(migrated); clearProfile("A"); clearProfile("B");
        }
        return List.copyOf(migrated);
    }

    private String decode(Base64.Decoder decoder, JsonElement value) {
        return new String(decoder.decode(value.getAsString()), StandardCharsets.UTF_8);
    }

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

    public void saveCandidateRules(Collection<CandidateRule> rules) {
        JsonArray rows = new JsonArray();
        if (rules != null) for (CandidateRule rule : rules) rows.add(new Gson().toJsonTree(rule));
        data.setString("v4.candidateRules", rows.toString());
        data.setString("schemaVersion", Integer.toString(SCHEMA_VERSION));
    }

    public List<CandidateRule> loadCandidateRules() {
        String raw = data.getString("v4.candidateRules");
        if (raw == null || raw.isBlank()) return List.of();
        List<CandidateRule> result = new ArrayList<>();
        try {
            for (JsonElement element : JsonParser.parseString(raw).getAsJsonArray()) {
                CandidateRule rule = new Gson().fromJson(element, CandidateRule.class);
                if (rule != null) result.add(rule);
            }
        } catch (JsonParseException | IllegalStateException ignored) { return List.of(); }
        return List.copyOf(result);
    }
    private String safeKey(String value) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
}
