package com.adminsec.idor;

import com.google.gson.*;
import com.adminsec.idor.model.Reference;

import java.util.*;
import java.util.function.Predicate;

/** Bounded structural JSON inspection shared by detection and comparison. */
final class JsonInspector {
    private static final int MAX_DEPTH = 40;
    private static final int MAX_VALUES = 2_000;

    List<Reference> references(String body, String source, Predicate<String> identifierName,
                               java.util.function.Function<String, String> shape) {
        if (body == null || body.isBlank()) return List.of();
        try {
            JsonElement root = JsonParser.parseString(body);
            List<Reference> result = new ArrayList<>();
            walk(root, "$", "", source, identifierName, shape, result, 0);
            return result;
        } catch (JsonParseException ignored) {
            return List.of();
        }
    }

    JsonElement parse(String body) {
        if (body == null || body.isBlank()) return null;
        try { return JsonParser.parseString(body); }
        catch (JsonParseException ignored) { return null; }
    }

    private void walk(JsonElement element, String path, String key, String source,
                      Predicate<String> identifierName, java.util.function.Function<String, String> shape,
                      List<Reference> out, int depth) {
        if (element == null || element.isJsonNull() || depth > MAX_DEPTH || out.size() >= MAX_VALUES) return;
        if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet())
                walk(entry.getValue(), path + "." + entry.getKey(), entry.getKey(), source, identifierName, shape, out, depth + 1);
        } else if (element.isJsonArray()) {
            int i = 0;
            for (JsonElement child : element.getAsJsonArray())
                walk(child, path + "[" + i++ + "]", key, source, identifierName, shape, out, depth + 1);
        } else if (identifierName.test(key)) {
            String value = scalar(element);
            if (value.length() <= 256)
                out.add(new Reference(key, value, source.equals("Response") ? "Response JSON" : "JSON/body",
                        shape.apply(value), source, path, sensitivity(key)));
        }
    }

    private String scalar(JsonElement value) {
        if (!value.isJsonPrimitive()) return value.toString();
        JsonPrimitive p = value.getAsJsonPrimitive();
        return p.isString() ? p.getAsString() : p.toString();
    }

    static String sensitivity(String name) {
        String n = name == null ? "" : name.toLowerCase(Locale.ROOT);
        return n.matches(".*(patient|medical|payment|card|credential|admin|permission|tenant|account).*id.*") ? "Sensitive" : "Normal";
    }
}
