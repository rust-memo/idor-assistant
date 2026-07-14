package com.adminsec.idor;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

@FunctionalInterface
public interface HttpSender {
    HttpRequestResponse send(HttpRequest request);
}
