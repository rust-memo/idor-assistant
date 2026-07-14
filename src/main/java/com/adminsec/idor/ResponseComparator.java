package com.adminsec.idor;

import com.google.gson.*;
import com.adminsec.idor.model.Reference;

import java.util.*;
import java.util.regex.Pattern;

public final class ResponseComparator {
    private volatile Set<String> volatileFields = Set.of(
            "timestamp", "time", "date", "nonce", "request_id", "requestid", "trace_id", "traceid", "correlation_id");
    private static final Pattern VOLATILE_TEXT = Pattern.compile("(?i)(\"(?:timestamp|time|date|nonce|request_?id|trace_?id)\"\\s*:\\s*)\"?[^\",}]+\"?");
    private static final Pattern DENIED = Pattern.compile("(?i)\\b(unauthori[sz]ed|forbidden|access denied|permission denied|not allowed|login required)\\b");
    private static final Pattern SESSION = Pattern.compile("(?i)\\b(?:invalid|expired|missing|required|failed)\\s+(?:csrf|xsrf|nonce|token|session)\\b|"
            + "\\b(?:csrf|xsrf|nonce|token|session)(?:\\s+token)?\\s+(?:is\\s+)?(?:invalid|expired|missing|required|failed)\\b");
    private static final Pattern LOGIN = Pattern.compile("(?i)(<form[^>]+(?:login|signin)|name=[\"']?(?:password|passwd)|/login|sign[ -]?in)");
    private static final Pattern WAF = Pattern.compile("(?i)\\b(web application firewall|cloudflare|akamai|imperva|request blocked|security policy)\\b");

    public record Result(String status, String detail, double similarity, boolean ownershipEvidence,
                         List<String> indicators, String confidence) {
        public Result(String status, String detail, double similarity) {
            this(status, detail, similarity, false, List.of(), "Low");
        }
    }

    public void configureVolatileFields(Collection<String> names) {
        Set<String> configured = new LinkedHashSet<>(Set.of("timestamp", "time", "date", "nonce", "request_id", "requestid", "trace_id", "traceid", "correlation_id"));
        names.stream().map(s -> s.trim().toLowerCase(Locale.ROOT)).filter(s -> !s.isBlank()).forEach(configured::add);
        volatileFields = Set.copyOf(configured);
    }

    public Result compare(int baselineStatus, String baselineBody, int crossStatus, String crossBody) {
        return compare(baselineStatus, baselineBody, crossStatus, crossBody, List.of());
    }

    public Result compare(int baselineStatus, String baselineBody, int crossStatus, String crossBody,
                          Collection<Reference> expectedReferences) {
        String base = normalize(baselineBody);
        String cross = normalize(crossBody);
        double similarity = dice(base, cross);
        List<String> indicators = new ArrayList<>();
        boolean ownership = ownershipEvidence(baselineBody, crossBody, expectedReferences);
        if (ownership) indicators.add("shared object identity");

        String crossRaw = crossBody == null ? "" : crossBody;
        if (crossStatus == 429) return result("Inconclusive", "Other account was rate limited", similarity, ownership, indicators, "Low");
        if (SESSION.matcher(crossRaw).find()) return result("Inconclusive", "Other-account response indicates CSRF, nonce, token, or session failure", similarity, ownership, indicators, "Low");
        if (LOGIN.matcher(crossRaw).find()) return result("Inconclusive", "Other account received a login page or authentication redirect", similarity, ownership, indicators, "Low");
        if (WAF.matcher(crossRaw).find()) return result("Inconclusive", "A WAF or security gateway appears to have handled the request", similarity, ownership, indicators, "Low");
        if (crossStatus >= 300 && crossStatus < 400) return result("Inconclusive", "Redirect response needs manual authentication-flow review", similarity, ownership, indicators, "Low");
        if (crossStatus == 401 || crossStatus == 403 || DENIED.matcher(crossRaw).find())
            return result("Likely protected", "Other-account request was explicitly denied", similarity, ownership, indicators, "High");
        if (crossStatus == 404 && successful(baselineStatus))
            return result("Likely protected", "Object is hidden from the other account (404)", similarity, ownership, indicators, "Medium");
        if (successful(baselineStatus) && successful(crossStatus) && ownership && similarity >= 0.85)
            return result("Suspicious access", "Both accounts received highly similar successful responses containing the same object identity", similarity, true, indicators, "High");
        if (successful(crossStatus) && ownership && similarity >= 0.50)
            return result("Suspicious access", "Other account received a materially similar response with matching object identity", similarity, true, indicators, "Medium");
        if (successful(crossStatus) && similarity >= 0.85)
            return result("Inconclusive", "Responses are similar, but no object-ownership evidence was found", similarity, false, indicators, "Low");
        return result("Inconclusive", "Response difference needs manual review", similarity, ownership, indicators, "Low");
    }

    private Result result(String status, String detail, double similarity, boolean ownership,
                          List<String> indicators, String confidence) {
        return new Result(status, detail, similarity, ownership, List.copyOf(indicators), confidence);
    }

    private boolean successful(int status) { return status >= 200 && status < 300; }

    String normalize(String body) {
        if (body == null) return "";
        try { return canonical(JsonParser.parseString(body)).toLowerCase(Locale.ROOT); }
        catch (JsonParseException ignored) {
            return VOLATILE_TEXT.matcher(body).replaceAll("$1<volatile>").replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
        }
    }

    private String canonical(JsonElement element) {
        if (element == null || element.isJsonNull()) return "null";
        if (element.isJsonArray()) {
            List<String> values = new ArrayList<>();
            element.getAsJsonArray().forEach(e -> values.add(canonical(e)));
            return "[" + String.join(",", values) + "]";
        }
        if (element.isJsonObject()) {
            List<String> names = new ArrayList<>(element.getAsJsonObject().keySet());
            names.sort(String.CASE_INSENSITIVE_ORDER);
            List<String> fields = new ArrayList<>();
            for (String name : names) {
                if (!volatileFields.contains(name.toLowerCase(Locale.ROOT)))
                    fields.add(new Gson().toJson(name) + ":" + canonical(element.getAsJsonObject().get(name)));
            }
            return "{" + String.join(",", fields) + "}";
        }
        return element.toString();
    }

    private boolean ownershipEvidence(String baseline, String cross, Collection<Reference> expected) {
        Set<String> expectedValues = new LinkedHashSet<>();
        for (Reference r : expected)
            if ("Request".equals(r.source()) && r.value() != null && !r.value().isBlank() && !r.value().startsWith("$"))
                expectedValues.add(r.value());
        Map<String, Set<String>> baseIds = identityValues(baseline);
        Map<String, Set<String>> crossIds = identityValues(cross);
        for (Map.Entry<String, Set<String>> entry : baseIds.entrySet()) {
            Set<String> other = crossIds.getOrDefault(entry.getKey(), Set.of());
            for (String value : entry.getValue())
                if (other.contains(value) && (expectedValues.isEmpty() || expectedValues.contains(value))) return true;
        }
        for (Reference reference : expected) {
            if (!"Request".equals(reference.source()) || reference.value() == null || reference.value().isBlank()) continue;
            if (textualIdentity(baseline, reference) && textualIdentity(cross, reference)) return true;
        }
        return false;
    }

    private boolean textualIdentity(String body, Reference reference) {
        if (body == null) return false;
        String name = Pattern.quote(reference.name()); String value = Pattern.quote(reference.value());
        Pattern contextual = Pattern.compile("(?is)(?:[<\"']" + name + "[>\"']\\s*[:=]?\\s*[\"']?" + value
                + "(?:[<\"'\\s,}])|" + name + "\\s*=\\s*[\"']" + value + "[\"'])");
        return contextual.matcher(body).find();
    }

    private Map<String, Set<String>> identityValues(String body) {
        Map<String, Set<String>> found = new LinkedHashMap<>();
        if (body == null) return found;
        try { collectIdentities(JsonParser.parseString(body), found, 0); }
        catch (JsonParseException ignored) { }
        return found;
    }

    private void collectIdentities(JsonElement element, Map<String, Set<String>> out, int depth) {
        if (element == null || element.isJsonNull() || depth > 40) return;
        if (element.isJsonArray()) element.getAsJsonArray().forEach(e -> collectIdentities(e, out, depth + 1));
        else if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : element.getAsJsonObject().entrySet()) {
                String key = e.getKey().replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT).replace('-', '_');
                if ((key.equals("id") || key.endsWith("_id")) && e.getValue().isJsonPrimitive())
                    out.computeIfAbsent(key, ignored -> new LinkedHashSet<>()).add(e.getValue().getAsString());
                collectIdentities(e.getValue(), out, depth + 1);
            }
        }
    }

    double dice(String a, String b) {
        if (a.equals(b)) return 1.0;
        if (a.length() < 2 || b.length() < 2) return 0.0;
        Map<String, Integer> grams = new HashMap<>();
        for (int i = 0; i < a.length() - 1; i++) grams.merge(a.substring(i, i + 2), 1, Integer::sum);
        int overlap = 0;
        for (int i = 0; i < b.length() - 1; i++) {
            String gram = b.substring(i, i + 2); int count = grams.getOrDefault(gram, 0);
            if (count > 0) { overlap++; grams.put(gram, count - 1); }
        }
        return (2.0 * overlap) / ((a.length() - 1) + (b.length() - 1));
    }
}
