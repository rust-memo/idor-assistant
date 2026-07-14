package com.adminsec.idor;

import burp.api.montoya.http.message.params.HttpParameterType;

import java.util.Locale;

/** A session-bound value that must change together with an identity. */
public record SessionSubstitution(Location location, String name, String value) {
    public enum Location { URL, BODY, COOKIE, JSON, XML, XML_ATTRIBUTE, MULTIPART_ATTRIBUTE }

    public SessionSubstitution {
        location = location == null ? Location.BODY : location;
        name = name == null ? "" : name;
        value = value == null ? "" : value;
    }

    public static SessionSubstitution from(String type, String name, String value) {
        try { return new SessionSubstitution(Location.valueOf(type.toUpperCase(Locale.ROOT)), name, value); }
        catch (Exception ignored) { return new SessionSubstitution(Location.BODY, name, value); }
    }

    public HttpParameterType parameterType() {
        return HttpParameterType.valueOf(location.name());
    }
}
