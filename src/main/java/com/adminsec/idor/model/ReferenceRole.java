package com.adminsec.idor.model;

/** Semantic role used to keep authentication and operational identifiers out of object candidates. */
public enum ReferenceRole {
    OBJECT,
    AUTH_CONTEXT,
    PAGINATION,
    TELEMETRY,
    UNKNOWN
}
