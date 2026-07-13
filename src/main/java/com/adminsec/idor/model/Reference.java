package com.adminsec.idor.model;

/** A possible object reference and enough provenance to review it safely. */
public record Reference(String name, String value, String location, String shape,
                        String source, String structuralPath, String sensitivity) {
    public Reference(String name, String value, String location, String shape) {
        this(name, value, location, shape, "Request", name == null ? "" : name, "Normal");
    }

    public Reference {
        name = name == null ? "" : name;
        value = value == null ? "" : value;
        location = location == null ? "" : location;
        shape = shape == null ? "" : shape;
        source = source == null ? "Request" : source;
        structuralPath = structuralPath == null ? "" : structuralPath;
        sensitivity = sensitivity == null ? "Normal" : sensitivity;
    }
}
