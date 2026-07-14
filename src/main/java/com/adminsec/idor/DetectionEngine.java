package com.adminsec.idor;

import com.adminsec.idor.model.*;

import javax.xml.stream.*;
import java.io.StringReader;
import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DetectionEngine {
    private final JsonInspector json = new JsonInspector();
    private volatile Set<String> customAllow = Set.of();
    private volatile Set<String> customDeny = Set.of();
    private volatile List<String> ignoredPaths = List.of();
    private volatile List<CandidateRule> rules = List.of();
    private volatile int maxRequestBody = 1_048_576;
    private volatile int maxResponseBody = 2_097_152;

    private static final Set<String> EXACT = Set.of(
            "id", "uid", "uuid", "guid", "object_id", "record_id", "resource_id", "reference_id",
            "user_id", "member_id", "customer_id", "profile_id", "owner_id", "account_id", "tenant_id",
            "organization_id", "org_id", "company_id", "team_id", "group_id", "workspace_id", "project_id",
            "order_id", "invoice_id", "transaction_id", "payment_id", "payment_method_id", "subscription_id",
            "ticket_id", "case_id", "issue_id", "message_id", "thread_id", "conversation_id", "comment_id",
            "file_id", "folder_id", "document_id", "document", "attachment_id", "download_id", "report_id",
            "export_id", "address_id", "booking_id", "reservation_id", "appointment_id", "patient_id",
            "medical_record_id", "prescription_id", "claim_id", "api_key_id", "credential_id", "role_id",
            "permission_id", "admin_id", "employee_id", "device_id", "webhook_id", "job_id", "task_id"
    );
    private static final Set<String> GENERIC = Set.of("id", "uid", "uuid", "guid", "key", "ref");
    private static final Set<String> IGNORED = Set.of(
            "session_id", "request_id", "trace_id", "correlation_id", "span_id", "analytics_id", "csrf_token",
            "xsrf_token", "captcha_id", "page_id", "sort_id", "filter_id", "locale_id", "language_id",
            "timestamp_id", "time_id", "version_id", "build_id", "event_id", "visitor_id",
            "cursor_id", "offset_id", "limit_id"
    );
    private static final Set<String> IDENTITY_HEADERS = Set.of(
            "x-user-id", "x-account-id", "x-customer-id", "x-member-id", "x-tenant-id", "x-organization-id",
            "x-org-id", "x-owner-id", "x-profile-id", "x-client-id"
    );
    private static final Set<String> OBJECT_HEADERS = Set.of("x-resource-id", "x-object-id");
    private static final Set<String> PAGINATION = Set.of(
            "page", "page_id", "page_size", "limit", "offset", "cursor", "after", "before", "sort", "sort_id",
            "filter", "filter_id", "cursor_id", "offset_id", "limit_id", "start", "end", "from", "to"
    );
    private static final Set<String> TELEMETRY = Set.of(
            "request_id", "trace_id", "correlation_id", "span_id", "analytics_id", "event_id", "visitor_id",
            "build_id", "version_id", "revision_id", "timestamp_id", "time_id", "device_id"
    );
    private static final Set<String> FEATURES = Set.of(
            "user", "profile", "account", "member", "customer", "order", "invoice", "payment", "card",
            "subscription", "transaction", "refund", "ticket", "case", "issue", "message", "conversation",
            "comment", "file", "folder", "document", "attachment", "download", "upload", "export", "report",
            "address", "booking", "reservation", "appointment", "patient", "medical", "prescription", "claim",
            "credential", "admin", "role", "permission", "project", "workspace", "organization", "tenant",
            "webhook", "notification", "resource", "object", "record", "employee", "team", "group", "company"
    );
    private static final Set<String> OWNER = Set.of(
            "user", "account", "member", "customer", "client", "owner", "tenant", "org", "organization",
            "company", "team", "group", "workspace", "patient", "employee", "admin", "role", "permission"
    );
    private static final Set<String> NON_RESOURCES = Set.of(
            "api", "rest", "graphql", "rpc", "status", "health", "metrics", "search", "query", "list", "lists",
            "page", "pages", "limit", "offset", "sort", "filter", "events", "analytics", "static", "assets",
            "public", "callback", "oauth", "login", "logout", "auth", "token", "refresh", "version", "build",
            "year", "month", "day", "hour", "minute", "download", "upload", "preview", "count", "summary"
    );
    private static final Set<String> LIST_ENDPOINTS = Set.of("search", "query", "list", "all", "feed", "index");

    private static final Pattern UUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Pattern HEX = Pattern.compile("(?i)^[0-9a-f]{16,64}$");
    private static final Pattern ULID = Pattern.compile("(?i)^[0-9A-HJKMNP-TV-Z]{26}$");
    private static final Pattern NUMBER = Pattern.compile("^[0-9]{1,20}$");
    private static final Pattern OPAQUE = Pattern.compile("^[A-Za-z0-9_-]{12,160}$");
    private static final Pattern BODY_IDS = Pattern.compile("(?i)[\"']([A-Za-z][A-Za-z0-9_.-]*(?:id|uuid|guid|key|ref))[\"']\\s*:\\s*[\"']?([A-Za-z0-9_:.@/=-]{1,160})");
    private static final Pattern GRAPHQL = Pattern.compile("\\b([A-Za-z][A-Za-z0-9_]*(?:Id|ID|Uuid|UUID|Guid|GUID|Key|Ref))\\s*:\\s*(?:\"([^\"]+)\"|([0-9]+)|\\$([A-Za-z][A-Za-z0-9_]*))");
    private static final Set<String> STATIC = Set.of("js", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "mp4", "mp3", "pdf");

    public record Input(String method, String url, String path, Map<String, String> headers,
                        List<Reference> parameters, String body, String responseBody, int statusCode) {}

    private record ScoredReference(Reference reference, int score, boolean ignored, boolean allowed,
                                   List<String> reasons) {}

    public void configure(Collection<String> allowNames, Collection<String> denyNames, Collection<String> pathDenylist) {
        customAllow = normalizeSet(allowNames);
        customDeny = normalizeSet(denyNames);
        ignoredPaths = pathDenylist.stream().map(String::trim).filter(s -> !s.isBlank())
                .map(s -> s.toLowerCase(Locale.ROOT)).toList();
    }

    public void configureRules(Collection<CandidateRule> candidateRules) {
        rules = candidateRules == null ? List.of() : List.copyOf(candidateRules);
    }

    public void configureLimits(int requestBytes, int responseBytes) {
        maxRequestBody = Math.max(16_384, Math.min(requestBytes, 10_485_760));
        maxResponseBody = Math.max(16_384, Math.min(responseBytes, 20_971_520));
    }

    public Optional<Assessment> analyze(Input input) {
        String path = input.path() == null ? "/" : input.path();
        if (ignoredPaths.stream().anyMatch(path.toLowerCase(Locale.ROOT)::contains)) return Optional.empty();
        int dot = path.lastIndexOf('.');
        if (dot >= 0 && STATIC.contains(path.substring(dot + 1).toLowerCase(Locale.ROOT))) return Optional.empty();

        List<Reference> refs = new ArrayList<>();
        for (Reference parameter : safe(input.parameters())) {
            if (isIdentifierName(parameter.name())) refs.add(enrich(parameter, "Request", parameter.name(), path));
        }
        for (Map.Entry<String, String> header : safe(input.headers()).entrySet()) {
            String headerName = header.getKey().toLowerCase(Locale.ROOT);
            if (IDENTITY_HEADERS.contains(headerName) || OBJECT_HEADERS.contains(headerName)) {
                ReferenceRole role = IDENTITY_HEADERS.contains(headerName) ? ReferenceRole.AUTH_CONTEXT : ReferenceRole.OBJECT;
                refs.add(new Reference(header.getKey(), header.getValue(), "Header", shape(header.getValue()),
                        "Request", "header." + header.getKey(), JsonInspector.sensitivity(header.getKey()), role,
                        List.of(role == ReferenceRole.AUTH_CONTEXT ? "identity header" : "object header")));
            }
        }
        collectPath(path, refs);
        collectBody(input.body(), path, refs);
        collectXml(input.body(), path, refs);
        refs = deduplicate(refs);
        if (refs.isEmpty()) return Optional.empty();

        collectResponseReferences(input.responseBody(), path, refs);
        refs = deduplicate(refs);
        String endpoint = endpointTemplate(path);
        String host = host(input.url());
        List<Reference> requestRefs = refs.stream().filter(r -> "Request".equals(r.source())).toList();
        List<Reference> responseRefs = refs.stream().filter(r -> "Response".equals(r.source())).toList();
        List<ScoredReference> scored = requestRefs.stream()
                .map(ref -> score(ref, host, input.method(), endpoint, path)).toList();
        List<Reference> outputRefs = new ArrayList<>(scored.stream()
                .filter(value -> value.allowed() || value.ignored()
                        || !Set.of(ReferenceRole.AUTH_CONTEXT, ReferenceRole.PAGINATION, ReferenceRole.TELEMETRY)
                        .contains(value.reference().role()))
                .map(ScoredReference::reference).toList());
        outputRefs.addAll(responseRefs);
        List<ScoredReference> eligible = scored.stream()
                .filter(value -> !value.ignored() && (value.allowed()
                        || (value.reference().role() != ReferenceRole.AUTH_CONTEXT
                        && value.reference().role() != ReferenceRole.PAGINATION
                        && value.reference().role() != ReferenceRole.TELEMETRY)))
                .toList();
        if (eligible.isEmpty()) {
            boolean userIgnored = scored.stream().anyMatch(ScoredReference::ignored);
            if (!userIgnored) return Optional.empty();
            return Optional.of(new Assessment(30, "Low", endpoint, outputRefs, List.of("matched a scoped false-positive rule"),
                    CandidateDisposition.SUPPRESSED, "Suppressed by a user rule"));
        }

        ScoredReference best = eligible.stream().max(Comparator.comparingInt(ScoredReference::score)).orElseThrow();
        int score = best.score();
        LinkedHashSet<String> reasons = new LinkedHashSet<>(best.reasons());
        if (eligible.size() > 1) { score += 5; reasons.add("multiple object-reference signals"); }
        if (Set.of("PUT", "PATCH", "DELETE").contains(upper(input.method()))) {
            score += 10; reasons.add("state-changing method");
        } else if ("POST".equals(upper(input.method()))) {
            score += 5; reasons.add("request body/action method");
        }
        if (correlated(requestRefs, responseRefs)) {
            score += 10; reasons.add("request reference correlated with response");
        }
        if (isListEndpoint(path) && best.score() < 55) {
            score -= 15; reasons.add("list/search endpoint penalty");
        }
        score = Math.max(0, Math.min(score, 100));
        boolean explicitlyAllowed = eligible.stream().anyMatch(ScoredReference::allowed);
        CandidateDisposition disposition = explicitlyAllowed || score >= 55
                ? CandidateDisposition.ACTIVE : CandidateDisposition.SUPPRESSED;
        if (score < 30 && !explicitlyAllowed) return Optional.empty();
        String priority = score >= 75 ? "High" : score >= 55 ? "Medium" : "Low";
        String suppressionReason = disposition == CandidateDisposition.SUPPRESSED
                ? (score < 55 ? "Insufficient independent object-reference evidence" : "Suppressed by rule") : "";
        return Optional.of(new Assessment(score, priority, endpoint, outputRefs, List.copyOf(reasons), disposition, suppressionReason));
    }

    public boolean isIdentifierName(String raw) {
        String name = normalize(raw);
        if (name.isBlank() || customDeny.contains(name)) return false;
        if (customAllow.contains(name)) return true;
        if (IGNORED.contains(name)) return false;
        return EXACT.contains(name) || List.of("_id", "_ids", "_uuid", "_guid", "_key", "_ref")
                .stream().anyMatch(name::endsWith);
    }

    public String endpointTemplate(String rawPath) {
        String path = rawPath == null ? "/" : rawPath.split("\\?", 2)[0];
        String[] segments = path.split("/", -1);
        for (int i = 0; i < segments.length; i++) if (!shape(segments[i]).isBlank()) segments[i] = "{id}";
        return String.join("/", segments);
    }

    public String shape(String value) {
        if (value == null || value.isBlank() || value.length() > 256 || value.startsWith("$")) return "";
        if (UUID.matcher(value).matches()) return "UUID";
        if (ULID.matcher(value).matches()) return "ULID";
        if (NUMBER.matcher(value).matches()) return value.length() >= 16 ? "Snowflake/numeric ID" : "numeric ID";
        if (HEX.matcher(value).matches()) return "hex/object ID";
        if (OPAQUE.matcher(value).matches() && value.chars().anyMatch(Character::isDigit)) return "opaque/base64-like ID";
        return "";
    }

    private ScoredReference score(Reference reference, String host, String method, String endpoint, String path) {
        String name = normalize(reference.name());
        Optional<CandidateRule> allow = matchingRule(CandidateRule.Action.ALLOW, host, method, endpoint, reference);
        Optional<CandidateRule> ignore = matchingRule(CandidateRule.Action.IGNORE, host, method, endpoint, reference);
        if (allow.isPresent()) return new ScoredReference(withEvidence(reference, List.of("scoped allow rule")), 100,
                false, true, List.of("explicit scoped allow rule"));
        if (ignore.isPresent()) return new ScoredReference(withEvidence(reference, List.of("scoped ignore rule")), 0,
                true, false, List.of(ignore.get().reason()));
        if (!customAllow.contains(name)
                && Set.of(ReferenceRole.AUTH_CONTEXT, ReferenceRole.PAGINATION, ReferenceRole.TELEMETRY).contains(reference.role()))
            return new ScoredReference(reference, 0, false, false, List.of(reference.role().name().toLowerCase(Locale.ROOT)));

        int value = 0;
        List<String> evidence = new ArrayList<>();
        boolean customAllowed = customAllow.contains(name);
        if (customAllowed) { value += 70; evidence.add("custom identifier allowlist"); }
        else if ("Path".equals(reference.location())) {
            if (isKnownResource(name)) { value += 30; evidence.add("known resource path segment"); }
            else if (isPlausibleResource(name)) { value += 20; evidence.add("resource-like path segment"); }
        } else if (OBJECT_HEADERS.contains(reference.name().toLowerCase(Locale.ROOT))) {
            value += 30; evidence.add("explicit object header");
        } else if (GENERIC.contains(name)) {
            value += 10; evidence.add("generic identifier name");
        } else if (EXACT.contains(name)) {
            value += 30; evidence.add("known object field");
        } else if (hasIdentifierSuffix(name)) {
            value += 25; evidence.add("object identifier suffix");
        }
        if (!reference.shape().isBlank()) { value += 25; evidence.add("identifier-shaped value"); }
        if (hasResourceContext(path, name)) { value += 20; evidence.add("object/resource endpoint context"); }
        if ("Sensitive".equals(reference.sensitivity())) { value += 10; evidence.add("sensitive object reference"); }
        if (OWNER.stream().anyMatch(owner -> tokenMatches(name, owner))) { value += 10; evidence.add("owner/account field"); }
        if (reference.location().toLowerCase(Locale.ROOT).contains("cookie")) {
            value -= 15; evidence.add("cookie context penalty");
        }
        Reference enriched = new Reference(reference.name(), reference.value(), reference.location(), reference.shape(),
                reference.source(), reference.structuralPath(), reference.sensitivity(), reference.role(), evidence);
        return new ScoredReference(enriched, Math.max(value, 0), false, customAllowed, evidence);
    }

    private void collectPath(String raw, List<Reference> refs) {
        String[] parts = raw.split("\\?", 2)[0].split("/");
        for (int i = 0; i < parts.length; i++) {
            String value = parts[i];
            String foundShape = shape(value);
            if (foundShape.isBlank()) continue;
            if (value.length() == 4 && NUMBER.matcher(value).matches()) {
                int year = Integer.parseInt(value);
                if (year >= 1900 && year <= 2100) continue;
            }
            String previous = i > 0 ? parts[i - 1] : "path";
            ReferenceRole role = role(previous, "Path");
            if (Set.of(ReferenceRole.PAGINATION, ReferenceRole.TELEMETRY, ReferenceRole.AUTH_CONTEXT).contains(role)) continue;
            refs.add(new Reference(previous, value, "Path", foundShape, "Request", "path[" + i + "]",
                    JsonInspector.sensitivity(previous), role, List.of()));
        }
    }

    private void collectBody(String body, String path, List<Reference> refs) {
        if (body == null || body.length() > maxRequestBody) return;
        List<Reference> structured = json.references(body, "Request", this::isIdentifierName, this::shape);
        structured.forEach(ref -> refs.add(enrich(ref, "Request", ref.structuralPath(), path)));
        if (structured.isEmpty()) {
            Matcher fallback = BODY_IDS.matcher(body);
            while (fallback.find()) if (isIdentifierName(fallback.group(1))) {
                Reference raw = new Reference(fallback.group(1), fallback.group(2), "JSON/body", shape(fallback.group(2)),
                        "Request", fallback.group(1), JsonInspector.sensitivity(fallback.group(1)));
                refs.add(enrich(raw, "Request", raw.structuralPath(), path));
            }
        }
        Matcher gql = GRAPHQL.matcher(body);
        while (gql.find()) {
            if (gql.group(4) != null) continue; // symbolic values are represented by their concrete JSON variables
            String value = gql.group(2) != null ? gql.group(2) : gql.group(3);
            Reference raw = new Reference(gql.group(1), value, "GraphQL", shape(value), "Request",
                    "graphql." + gql.group(1), JsonInspector.sensitivity(gql.group(1)));
            refs.add(enrich(raw, "Request", raw.structuralPath(), path));
        }
    }

    private void collectXml(String body, String requestPath, List<Reference> refs) {
        if (body == null || body.length() > maxRequestBody || !body.stripLeading().startsWith("<")) return;
        try {
            XMLInputFactory factory = XMLInputFactory.newFactory();
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(body));
            Deque<String> path = new ArrayDeque<>();
            Deque<StringBuilder> text = new ArrayDeque<>();
            while (reader.hasNext() && refs.size() < 2_000) {
                int event = reader.next();
                if (event == XMLStreamConstants.START_ELEMENT) {
                    String element = reader.getLocalName(); path.addLast(element); text.addLast(new StringBuilder());
                    String structuralPath = "$./" + String.join("/", path);
                    for (int i = 0; i < reader.getAttributeCount(); i++) {
                        String name = reader.getAttributeLocalName(i); String value = reader.getAttributeValue(i);
                        if (isIdentifierName(name)) {
                            Reference raw = new Reference(name, value, "XML_ATTRIBUTE", shape(value), "Request",
                                    structuralPath + "/@" + name, JsonInspector.sensitivity(name));
                            refs.add(enrich(raw, "Request", raw.structuralPath(), requestPath));
                        }
                    }
                } else if ((event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA) && !text.isEmpty()) {
                    if (text.getLast().length() < 257) text.getLast().append(reader.getText());
                } else if (event == XMLStreamConstants.END_ELEMENT && !path.isEmpty()) {
                    String name = path.getLast(); String value = text.removeLast().toString().trim();
                    if (isIdentifierName(name) && !value.isBlank() && value.length() <= 256) {
                        Reference raw = new Reference(name, value, "XML", shape(value), "Request",
                                "$./" + String.join("/", path), JsonInspector.sensitivity(name));
                        refs.add(enrich(raw, "Request", raw.structuralPath(), requestPath));
                    }
                    path.removeLast();
                }
            }
            reader.close();
        } catch (XMLStreamException | IllegalArgumentException ignored) { }
    }

    private void collectResponseReferences(String body, String path, List<Reference> refs) {
        if (body == null || body.length() > maxResponseBody) return;
        json.references(body, "Response", this::isIdentifierName, this::shape).stream().limit(50)
                .map(ref -> enrich(ref, "Response", ref.structuralPath(), path)).forEach(refs::add);
    }

    private Reference enrich(Reference value, String source, String structuralPath, String requestPath) {
        ReferenceRole role = role(value.name(), value.location());
        if (role == ReferenceRole.UNKNOWN && hasResourceContext(requestPath, normalize(value.name()))) role = ReferenceRole.OBJECT;
        return new Reference(value.name(), value.value(), value.location(), shape(value.value()), source, structuralPath,
                JsonInspector.sensitivity(value.name()), role, value.evidence());
    }

    private ReferenceRole role(String rawName, String rawLocation) {
        String name = normalize(rawName);
        String location = rawLocation == null ? "" : rawLocation.toLowerCase(Locale.ROOT);
        if (location.contains("header") && IDENTITY_HEADERS.contains(rawName.toLowerCase(Locale.ROOT))) return ReferenceRole.AUTH_CONTEXT;
        if (location.contains("cookie") && (OWNER.stream().anyMatch(owner -> tokenMatches(name, owner))
                || name.contains("session") || name.contains("auth") || name.contains("token"))) return ReferenceRole.AUTH_CONTEXT;
        if (PAGINATION.contains(name)) return ReferenceRole.PAGINATION;
        if (TELEMETRY.contains(name)) return ReferenceRole.TELEMETRY;
        if (EXACT.contains(name) || hasIdentifierSuffix(name) || isKnownResource(name)) return ReferenceRole.OBJECT;
        return ReferenceRole.UNKNOWN;
    }

    private boolean correlated(List<Reference> request, List<Reference> response) {
        for (Reference left : request) for (Reference right : response) {
            if ((!left.value().isBlank() && left.value().equals(right.value()))
                    || (normalize(left.name()).equals(normalize(right.name())) && !right.value().isBlank())) return true;
        }
        return false;
    }

    private Optional<CandidateRule> matchingRule(CandidateRule.Action action, String host, String method,
                                                  String endpoint, Reference reference) {
        return rules.stream().filter(rule -> rule.action() == action && rule.matches(host, method, endpoint, reference))
                .reduce((first, second) -> second);
    }

    private boolean hasResourceContext(String path, String name) {
        if (isKnownResource(name)) return true;
        return pathTokens(path).stream().anyMatch(this::isKnownResource);
    }

    private boolean isListEndpoint(String path) {
        return pathTokens(path).stream().anyMatch(LIST_ENDPOINTS::contains);
    }

    private List<String> pathTokens(String path) {
        return Arrays.stream((path == null ? "" : path.toLowerCase(Locale.ROOT)).split("[^a-z0-9]+"))
                .filter(token -> !token.isBlank()).toList();
    }

    private boolean isKnownResource(String raw) {
        String token = normalize(raw);
        if (FEATURES.contains(token)) return true;
        if (token.endsWith("ies") && FEATURES.contains(token.substring(0, token.length() - 3) + "y")) return true;
        if (token.endsWith("es") && FEATURES.contains(token.substring(0, token.length() - 2))) return true;
        return token.endsWith("s") && token.length() > 3 && FEATURES.contains(token.substring(0, token.length() - 1));
    }

    private boolean isPlausibleResource(String raw) {
        String token = normalize(raw);
        return token.matches("[a-z][a-z0-9_-]{2,40}") && !NON_RESOURCES.contains(token)
                && !token.matches("v[0-9]+") && !PAGINATION.contains(token) && !TELEMETRY.contains(token);
    }

    private boolean tokenMatches(String normalizedName, String token) {
        return normalizedName.equals(token) || normalizedName.startsWith(token + "_")
                || normalizedName.endsWith("_" + token) || normalizedName.contains("_" + token + "_");
    }

    private boolean hasIdentifierSuffix(String name) {
        return List.of("_id", "_ids", "_uuid", "_guid", "_key", "_ref").stream().anyMatch(name::endsWith);
    }

    private List<Reference> deduplicate(List<Reference> refs) {
        Map<String, Reference> unique = new LinkedHashMap<>();
        refs.forEach(r -> unique.putIfAbsent(r.source() + "\u0000" + r.location() + "\u0000" + r.structuralPath()
                + "\u0000" + normalize(r.name()) + "\u0000" + r.value(), r));
        return new ArrayList<>(unique.values());
    }

    private Reference withEvidence(Reference reference, List<String> evidence) {
        return new Reference(reference.name(), reference.value(), reference.location(), reference.shape(), reference.source(),
                reference.structuralPath(), reference.sensitivity(), reference.role(), evidence);
    }

    private String host(String url) {
        try { return Optional.ofNullable(URI.create(url).getHost()).orElse(""); }
        catch (Exception ignored) { return ""; }
    }

    private String normalize(String raw) {
        return raw == null ? "" : raw.trim().replaceAll("([a-z0-9])([A-Z])", "$1_$2")
                .toLowerCase(Locale.ROOT).replace('-', '_').replace('.', '_').replaceAll("\\[[^]]*]", "_")
                .replaceAll("_+", "_").replaceAll("^_|_$", "");
    }

    private Set<String> normalizeSet(Collection<String> values) {
        Set<String> result = new LinkedHashSet<>();
        if (values != null) values.forEach(value -> { String normalized = normalize(value); if (!normalized.isBlank()) result.add(normalized); });
        return Set.copyOf(result);
    }

    private String upper(String value) { return value == null ? "" : value.toUpperCase(Locale.ROOT); }
    private <T> List<T> safe(List<T> value) { return value == null ? List.of() : value; }
    private <K, V> Map<K, V> safe(Map<K, V> value) { return value == null ? Map.of() : value; }
}
