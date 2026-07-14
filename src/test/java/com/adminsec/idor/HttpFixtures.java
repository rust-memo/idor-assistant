package com.adminsec.idor;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.*;
import burp.api.montoya.http.message.params.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

final class HttpFixtures {
    private HttpFixtures() { }

    static HttpHeader header(String name, String value) {
        HttpHeader header = mock(HttpHeader.class); when(header.name()).thenReturn(name); when(header.value()).thenReturn(value); return header;
    }

    static ParsedHttpParameter parameter(String name, String value, HttpParameterType type) {
        ParsedHttpParameter parameter = mock(ParsedHttpParameter.class);
        when(parameter.name()).thenReturn(name); when(parameter.value()).thenReturn(value); when(parameter.type()).thenReturn(type);
        return parameter;
    }

    static HttpRequest request(String method, String url, String body, boolean inScope,
                               List<HttpHeader> headers, List<ParsedHttpParameter> parameters) {
        HttpRequest request = mock(HttpRequest.class, RETURNS_SELF);
        when(request.method()).thenReturn(method); when(request.url()).thenReturn(url); when(request.bodyToString()).thenReturn(body);
        when(request.isInScope()).thenReturn(inScope); when(request.headers()).thenReturn(headers); when(request.parameters()).thenReturn(parameters);
        when(request.pathWithoutQuery()).thenReturn(URI.create(url).getPath()); when(request.path()).thenReturn(URI.create(url).getRawPath());
        when(request.query()).thenReturn(URI.create(url).getRawQuery());
        when(request.headerValue(anyString())).thenAnswer(invocation -> headers.stream()
                .filter(header -> header.name().equalsIgnoreCase(invocation.getArgument(0))).map(HttpHeader::value).findFirst().orElse(null));
        when(request.parameters(any(HttpParameterType.class))).thenAnswer(invocation -> parameters.stream()
                .filter(parameter -> parameter.type() == invocation.getArgument(0)).toList());
        when(request.hasParameter(anyString(), any(HttpParameterType.class))).thenAnswer(invocation -> parameters.stream()
                .anyMatch(parameter -> parameter.name().equals(invocation.getArgument(0)) && parameter.type() == invocation.getArgument(1)));
        HttpService service = mock(HttpService.class); when(service.host()).thenReturn(URI.create(url).getHost()); when(request.httpService()).thenReturn(service);
        return request;
    }

    static HttpRequest request(String method, String url) { return request(method, url, "", true, List.of(), List.of()); }

    static HttpRequestResponse message(HttpRequest request, int status, String body, String contentType) {
        HttpResponse response = mock(HttpResponse.class, RETURNS_SELF); when(response.statusCode()).thenReturn((short) status);
        when(response.bodyToString()).thenReturn(body); when(response.headerValue("Content-Type")).thenReturn(contentType);
        HttpRequestResponse message = mock(HttpRequestResponse.class); when(message.request()).thenReturn(request);
        when(message.response()).thenReturn(response); when(message.hasResponse()).thenReturn(true);
        return message;
    }
}
