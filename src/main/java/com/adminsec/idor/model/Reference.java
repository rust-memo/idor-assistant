package com.adminsec.idor.model;

import java.util.List;

/** A possible object reference and enough provenance to review it safely. */
public record Reference(String name, String value, String location, String shape,
                        String source, String structuralPath, String sensitivity,
                        ReferenceRole role, List<String> evidence) {
    public Reference(String name, String value, String location, String shape) {
        this(name, value, location, shape, "Request", name == null ? "" : name, "Normal",
                ReferenceRole.UNKNOWN, List.of());
    }

    public Reference(String name, String value, String location, String shape,
                     String source, String structuralPath, String sensitivity) {
        this(name, value, location, shape, source, structuralPath, sensitivity, ReferenceRole.UNKNOWN, List.of());
    }

    public Reference {
        name = name == null ? "" : name;
        value = value == null ? "" : value;
        location = location == null ? "" : location;
        shape = shape == null ? "" : shape;
        source = source == null ? "Request" : source;
        structuralPath = structuralPath == null ? "" : structuralPath;
        sensitivity = sensitivity == null ? "Normal" : sensitivity;
        role = role == null ? ReferenceRole.UNKNOWN : role;
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
    }
}
