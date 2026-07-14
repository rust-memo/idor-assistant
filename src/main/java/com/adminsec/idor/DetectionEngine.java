package com.adminsec.idor;

import com.adminsec.idor.model.Assessment;
import com.adminsec.idor.model.Reference;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.stream.*;
import java.io.StringReader;

public final class DetectionEngine {
    private final JsonInspector json = new JsonInspector();
    private volatile Set<String> customAllow = Set.of();
    private volatile Set<String> customDeny = Set.of();
    private volatile List<String> ignoredPaths = List.of();
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
    private static final Set<String> IGNORED = Set.of(
            "session_id", "request_id", "trace_id", "correlation_id", "span_id", "analytics_id", "csrf_token",
            "xsrf_token", "captcha_id", "page_id", "sort_id", "filter_id", "locale_id", "language_id"
    );
    private static final Set<String> ID_HEADERS = Set.of(
            "x-user-id", "x-account-id", "x-customer-id", "x-member-id", "x-tenant-id", "x-organization-id",
            "x-org-id", "x-owner-id", "x-resource-id", "x-object-id", "x-profile-id", "x-client-id"
    );
    private static final List<String> FEATURES = List.of(
            "user", "profile", "account", "member", "customer", "order", "invoice", "payment", "card",
            "subscription", "transaction", "refund", "ticket", "case", "issue", "message", "conversation",
            "comment", "file", "folder", "document", "attachment", "download", "upload", "export", "report",
            "address", "booking", "reservation", "appointment", "patient", "medical", "prescription", "claim",
            "api-key", "credential", "admin", "role", "permission", "project", "workspace", "organization",
            "tenant", "webhook", "notification"
    );
    private static final List<String> OWNER = List.of(
            "user", "account", "member", "customer", "client", "owner", "tenant", "org", "company", "team",
            "group", "workspace", "patient", "employee", "admin", "role", "permission"
    );
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

    public void configure(Collection<String> allowNames, Collection<String> denyNames, Collection<String> pathDenylist) {
        customAllow = normalizeSet(allowNames); customDeny = normalizeSet(denyNames);
        ignoredPaths = pathDenylist.stream().map(String::trim).filter(s -> !s.isBlank()).map(s -> s.toLowerCase(Locale.ROOT)).toList();
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
        for (Reference parameter : input.parameters()) {
            if (isIdentifierName(parameter.name())) refs.add(enrich(parameter, "Request", parameter.name()));
        }
        for (Map.Entry<String, String> header : input.headers().entrySet()) {
            if (ID_HEADERS.contains(header.getKey().toLowerCase(Locale.ROOT)))
                refs.add(new Reference(header.getKey(), header.getValue(), "Header", shape(header.getValue()),
                        "Request", "header." + header.getKey(), JsonInspector.sensitivity(header.getKey())));
        }
        collectPath(path, refs);
        collectBody(input.body(), refs);
        collectXml(input.body(), refs);
        refs = deduplicate(refs);
        if (refs.isEmpty()) return Optional.empty();
        int requestReferenceCount = refs.size();
        collectResponseReferences(input.responseBody(), refs);
        refs = deduplicate(refs);

        String lowerPath = path.toLowerCase(Locale.ROOT).replace('_', '-');
        List<String> featureHits = FEATURES.stream().filter(lowerPath::contains).distinct().toList();
        int score = 25;
        List<String> reasons = new ArrayList<>();
        reasons.add("object reference present");
        List<Reference> requestRefs = refs.stream().filter(r -> "Request".equals(r.source())).toList();
        if (requestRefs.stream().anyMatch(r -> EXACT.contains(normalize(r.name())))) { score += 10; reasons.add("known object field"); }
        if (requestRefs.stream().anyMatch(r -> OWNER.stream().anyMatch(normalize(r.name())::contains))) { score += 15; reasons.add("owner/account reference"); }
        if (requestRefs.stream().anyMatch(r -> !r.shape().isBlank())) { score += 15; reasons.add("identifier-shaped value"); }
        if (requestRefs.stream().anyMatch(r -> "Sensitive".equals(r.sensitivity()))) { score += 10; reasons.add("sensitive object reference"); }
        if (!featureHits.isEmpty()) { score += Math.min(15, 5 + featureHits.size() * 3); reasons.add("sensitive feature: " + String.join(", ", featureHits.stream().limit(3).toList())); }
        if (Set.of("PUT", "PATCH", "DELETE").contains(input.method())) { score += 10; reasons.add("state-changing method"); }
        else if ("POST".equals(input.method())) score += 5;
        if (input.statusCode() >= 200 && input.statusCode() < 300) { score += 5; reasons.add("successful response"); }
        if (refs.size() > requestReferenceCount) { score += 5; reasons.add("related object references returned in response"); }
        score = Math.min(score, 100);
        String priority = score >= 75 ? "High" : score >= 55 ? "Medium" : "Low";
        return Optional.of(new Assessment(score, priority, endpointTemplate(path), List.copyOf(refs), List.copyOf(reasons)));
    }

    public boolean isIdentifierName(String raw) {
        String name = normalize(raw);
        if (name.isBlank() || customDeny.contains(name) || IGNORED.contains(name)) return false;
        if (customAllow.contains(name)) return true;
        return EXACT.contains(name) || List.of("_id", "_ids", "_uuid", "_guid", "_key", "_ref").stream().anyMatch(name::endsWith);
    }

    public String endpointTemplate(String rawPath) {
        String path = rawPath == null ? "/" : rawPath.split("\\?", 2)[0];
        String[] segments = path.split("/", -1);
        for (int i = 0; i < segments.length; i++) if (!shape(segments[i]).isBlank()) segments[i] = "{id}";
        return String.join("/", segments);
    }

    public String shape(String value) {
        if (value == null || value.isBlank() || value.length() > 256) return "";
        if (UUID.matcher(value).matches()) return "UUID";
        if (ULID.matcher(value).matches()) return "ULID";
        if (NUMBER.matcher(value).matches()) return value.length() >= 16 ? "Snowflake/numeric ID" : "numeric ID";
        if (HEX.matcher(value).matches()) return "hex/object ID";
        if (OPAQUE.matcher(value).matches() && value.chars().anyMatch(Character::isDigit)) return "opaque/base64-like ID";
        return "";
    }

    private void collectPath(String raw, List<Reference> refs) {
        String path = raw.split("\\?", 2)[0];
        String[] parts = path.split("/");
        for (int i = 0; i < parts.length; i++) {
            String value = parts[i];
            String shape = shape(value);
            if (shape.isBlank()) continue;
            if (value.length() == 4 && NUMBER.matcher(value).matches()) {
                int year = Integer.parseInt(value); if (year >= 1900 && year <= 2100) continue;
            }
            String previous = i > 0 ? parts[i - 1] : "path";
            if (Set.of("page", "limit", "offset", "year", "month", "day").contains(previous.toLowerCase(Locale.ROOT))) continue;
            refs.add(new Reference(previous, value, "Path", shape, "Request", "path[" + i + "]", JsonInspector.sensitivity(previous)));
        }
    }

    private void collectBody(String body, List<Reference> refs) {
        if (body == null || body.length() > maxRequestBody) return;
        List<Reference> structured = json.references(body, "Request", this::isIdentifierName, this::shape);
        refs.addAll(structured);
        if (structured.isEmpty()) {
            Matcher jsonFallback = BODY_IDS.matcher(body);
            while (jsonFallback.find()) if (isIdentifierName(jsonFallback.group(1)))
                refs.add(new Reference(jsonFallback.group(1), jsonFallback.group(2), "JSON/body", shape(jsonFallback.group(2)),
                        "Request", jsonFallback.group(1), JsonInspector.sensitivity(jsonFallback.group(1))));
        }
        Matcher gql = GRAPHQL.matcher(body);
        while (gql.find()) {
            String value = gql.group(2) != null ? gql.group(2) : gql.group(3) != null ? gql.group(3) : "$" + gql.group(4);
            refs.add(new Reference(gql.group(1), value, "GraphQL", shape(value), "Request",
                    "graphql." + gql.group(1), JsonInspector.sensitivity(gql.group(1))));
        }
    }

    private void collectXml(String body, List<Reference> refs) {
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
                        if (isIdentifierName(name)) refs.add(new Reference(name, value, "XML_ATTRIBUTE", shape(value),
                                "Request", structuralPath + "/@" + name, JsonInspector.sensitivity(name)));
                    }
                } else if ((event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA) && !text.isEmpty()) {
                    if (text.getLast().length() < 257) text.getLast().append(reader.getText());
                } else if (event == XMLStreamConstants.END_ELEMENT && !path.isEmpty()) {
                    String name = path.getLast(); String value = text.removeLast().toString().trim();
                    if (isIdentifierName(name) && !value.isBlank() && value.length() <= 256)
                        refs.add(new Reference(name, value, "XML", shape(value), "Request",
                                "$./" + String.join("/", path), JsonInspector.sensitivity(name)));
                    path.removeLast();
                }
            }
            reader.close();
        } catch (XMLStreamException | IllegalArgumentException ignored) { }
    }

    private void collectResponseReferences(String body, List<Reference> refs) {
        if (body == null || body.length() > maxResponseBody) return;
        json.references(body, "Response", this::isIdentifierName, this::shape).stream().limit(50).forEach(refs::add);
    }

    private Reference enrich(Reference r, String source, String path) {
        return new Reference(r.name(), r.value(), r.location(), shape(r.value()), source, path, JsonInspector.sensitivity(r.name()));
    }
    private List<Reference> deduplicate(List<Reference> refs) {
        Map<String, Reference> unique = new LinkedHashMap<>();
        refs.forEach(r -> unique.putIfAbsent(r.source() + "\u0000" + r.location() + "\u0000" + r.structuralPath() + "\u0000" + normalize(r.name()) + "\u0000" + r.value(), r));
        return new ArrayList<>(unique.values());
    }
    private String normalize(String raw) {
        return raw == null ? "" : raw.trim().replaceAll("([a-z0-9])([A-Z])", "$1_$2")
                .toLowerCase(Locale.ROOT).replace('-', '_').replace('.', '_').replaceAll("\\[[^]]*]", "_")
                .replaceAll("_+", "_").replaceAll("^_|_$", "");
    }
    private Set<String> normalizeSet(Collection<String> values) {
        Set<String> result = new LinkedHashSet<>(); values.forEach(v -> { String n = normalize(v); if (!n.isBlank()) result.add(n); }); return Set.copyOf(result);
    }
}
