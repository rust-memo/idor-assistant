package com.adminsec.idor;

import com.adminsec.idor.model.Candidate;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.List;
import java.util.stream.Collectors;

public final class CsvExporter {
    public void export(Path path, List<Candidate> candidates) throws IOException {
        try (BufferedWriter out = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            out.write("score,priority,method,url,endpoint,references,reasons,review,comparison,comparison_detail\n");
            for (Candidate c : candidates) {
                String references = c.assessment().references().stream().map(r -> r.name() + "@" + r.location()).collect(Collectors.joining("; "));
                writeRow(out, String.valueOf(c.assessment().score()), c.assessment().priority(), c.message().request().method(),
                        stripQuery(c.message().request().url()), c.assessment().endpointTemplate(), references,
                        String.join("; ", c.assessment().reasons()), c.reviewStatus(), c.comparisonStatus(), c.comparisonDetail());
            }
        }
    }

    private String stripQuery(String url) { int q = url.indexOf('?'); return q < 0 ? url : url.substring(0, q); }
    private void writeRow(Writer out, String... values) throws IOException {
        for (int i = 0; i < values.length; i++) {
            if (i > 0) out.write(',');
            String value = values[i] == null ? "" : values[i];
            if (!value.isEmpty() && "=+-@".indexOf(value.charAt(0)) >= 0) value = "'" + value;
            out.write('"'); out.write(value.replace("\"", "\"\"")); out.write('"');
        }
        out.write('\n');
    }
}
