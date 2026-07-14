package com.adminsec.idor;

import burp.api.montoya.http.message.requests.HttpRequest;

@FunctionalInterface
public interface ScopeGuard {
    boolean isAllowed(HttpRequest request);
}
