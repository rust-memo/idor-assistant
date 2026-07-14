package com.adminsec.idor;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.adminsec.idor.model.ComparisonEvidence;
import com.adminsec.idor.model.Reference;

import javax.swing.text.MutableAttributeSet;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;
import javax.xml.stream.*;
import java.io.StringReader;
import java.util.*;

/** Content-aware comparison with baseline-stability and authentication barrier checks. */
public final class ResponseEvidenceComparator {
    private final ResponseComparator core = new ResponseComparator();

    public void configureVolatileFields(Collection<String> names) { core.configureVolatileFields(names); }

    public ComparisonEvidence compare(HttpRequestResponse original, HttpRequestResponse owner,
                                      HttpRequestResponse cross, Collection<Reference> expectedReferences) {
        if (owner == null || cross == null || !owner.hasResponse() || !cross.hasResponse())
            return new ComparisonEvidence("Inconclusive", "One or both requests did not receive a response",
                    0, 0, false, List.of("missing response"), "Low", owner, cross);

        String ownerType = contentType(owner);
        String crossType = contentType(cross);
        ResponseComparator.Result barrier = core.compare(owner.response().statusCode(), owner.response().bodyToString(),
                cross.response().statusCode(), cross.response().bodyToString(), expectedReferences);
        if (isBarrier(barrier))
            return new ComparisonEvidence(barrier.status(), barrier.detail(), barrier.similarity(),
                    stability(original, owner, ownerType), barrier.ownershipEvidence(), barrier.indicators(),
                    barrier.confidence(), owner, cross);
        if (!compatible(ownerType, crossType))
            return new ComparisonEvidence("Inconclusive", "Owner and other-account responses use different content types",
                    0, stability(original, owner, ownerType), false,
                    List.of("content type changed: " + safe(ownerType) + " -> " + safe(crossType)), "Low", owner, cross);

        String ownerBody = normalize(owner.response().bodyToString(), ownerType);
        String crossBody = normalize(cross.response().bodyToString(), crossType);
        ResponseComparator.Result result = core.compare(owner.response().statusCode(), ownerBody,
                cross.response().statusCode(), crossBody, expectedReferences);
        double stability = stability(original, owner, ownerType);
        List<String> indicators = new ArrayList<>(result.indicators());
        indicators.add("content type: " + safe(ownerType));
        String status = result.status();
        String confidence = result.confidence();
        String detail = result.detail();
        if (stability > 0 && stability < 0.65 && "Suspicious access".equals(status)) {
            status = "Inconclusive"; confidence = "Low";
            detail = "The owner baseline changed materially; repeat after stabilizing the request";
            indicators.add("unstable owner baseline");
        } else if (stability == 0 && "High".equals(confidence)) {
            confidence = "Medium"; indicators.add("no comparable original baseline");
        }
        return new ComparisonEvidence(status, detail, result.similarity(), stability,
                result.ownershipEvidence(), indicators, confidence, owner, cross);
    }

    boolean authenticationFailure(ComparisonEvidence evidence) {
        String detail = evidence.detail().toLowerCase(Locale.ROOT);
        return detail.contains("session") || detail.contains("token") || detail.contains("login") || detail.contains("authentication");
    }

    private boolean isBarrier(ResponseComparator.Result result) {
        String detail = result.detail().toLowerCase(Locale.ROOT);
        return "Likely protected".equals(result.status()) || detail.contains("session") || detail.contains("token")
                || detail.contains("login") || detail.contains("rate limit") || detail.contains("waf") || detail.contains("security gateway");
    }

    private double stability(HttpRequestResponse original, HttpRequestResponse owner, String type) {
        if (original == null || !original.hasResponse() || original.response().statusCode() != owner.response().statusCode()) return 0;
        String before = core.normalize(normalize(original.response().bodyToString(), contentType(original)));
        String after = core.normalize(normalize(owner.response().bodyToString(), type));
        return core.dice(before, after);
    }

    private String normalize(String body, String type) {
        if (body == null) return "";
        String lower = type.toLowerCase(Locale.ROOT);
        if (lower.contains("html")) return htmlText(body);
        if (lower.contains("xml")) return xmlText(body);
        if (lower.startsWith("image/") || lower.contains("octet-stream") || lower.contains("pdf"))
            return "binary:length=" + body.length() + ":hash=" + Integer.toHexString(body.hashCode());
        return body;
    }

    private String htmlText(String body) {
        StringBuilder out = new StringBuilder();
        try {
            new ParserDelegator().parse(new StringReader(body), new HTMLEditorKit.ParserCallback() {
                @Override public void handleText(char[] data, int pos) { if (out.length() < 2_000_000) out.append(data).append(' '); }
                @Override public void handleStartTag(HTML.Tag tag, MutableAttributeSet attributes, int pos) {
                    if (tag == HTML.Tag.FORM) out.append(" <form> ");
                }
            }, true);
            return out.toString();
        } catch (Exception ignored) { return body; }
    }

    private String xmlText(String body) {
        StringBuilder out = new StringBuilder();
        try {
            XMLInputFactory factory = XMLInputFactory.newFactory();
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(body));
            while (reader.hasNext() && out.length() < 2_000_000) {
                int event = reader.next();
                if (event == XMLStreamConstants.START_ELEMENT) out.append('<').append(reader.getLocalName()).append('>');
                else if (event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA) out.append(reader.getText().trim());
            }
            reader.close(); return out.toString();
        } catch (Exception ignored) { return body; }
    }

    private String contentType(HttpRequestResponse message) {
        String value = message.response().headerValue("Content-Type");
        if (value == null || value.isBlank()) return message.response().inferredMimeType().toString();
        int semicolon = value.indexOf(';'); return (semicolon < 0 ? value : value.substring(0, semicolon)).trim().toLowerCase(Locale.ROOT);
    }

    private boolean compatible(String left, String right) {
        if (left.equalsIgnoreCase(right)) return true;
        return left.contains("json") && right.contains("json") || left.contains("html") && right.contains("html")
                || left.contains("xml") && right.contains("xml");
    }
    private String safe(String value) { return value == null || value.isBlank() ? "unknown" : value; }
}
