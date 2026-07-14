package com.adminsec.idor;

import burp.api.montoya.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.ui.contextmenu.*;

import javax.swing.*;
import java.awt.Component;
import java.util.*;

import static burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse;
import static burp.api.montoya.proxy.http.ProxyResponseReceivedAction.continueWith;
import static burp.api.montoya.proxy.http.ProxyResponseToBeSentAction.continueWith;

public final class IdorAssistantExtension implements BurpExtension {
    private MontoyaApi api;
    private CandidateCatalog catalog;
    private ProjectStore store;
    private ProfileManager profiles;
    private MessageAnalyzer analyzer;
    private ComparisonOrchestrator orchestrator;
    private IdorPanel panel;
    private volatile Thread historyScanner;

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("IDOR/BOLA Assistant");
        store = new ProjectStore(api.persistence().extensionData());
        profiles = new ProfileManager(store);
        catalog = new CandidateCatalog();
        DetectionEngine detectionEngine = new DetectionEngine();
        analyzer = new MessageAnalyzer(detectionEngine, store, profiles);
        orchestrator = new ComparisonOrchestrator(api.http()::sendRequest, request -> request.isInScope());
        panel = new IdorPanel(api, catalog, store, profiles, orchestrator, detectionEngine);
        panel.applySavedRules();
        api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("IDOR Assistant", panel);
        api.userInterface().registerContextMenuItemsProvider(new ProfileMenu());
        api.proxy().registerResponseHandler(new LiveProxyHandler());
        api.extension().registerUnloadingHandler(() -> {
            orchestrator.close();
            Thread scanner = historyScanner;
            if (scanner != null) scanner.interrupt();
        });
        historyScanner = new Thread(this::scanHistory, "idor-history-scan");
        historyScanner.setDaemon(true); historyScanner.start();
        api.logging().logToOutput("IDOR/BOLA Assistant loaded. Passive scanning never sends requests.");
    }

    private void scanHistory() {
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int limit = parseLimit(store.loadSetting("historyLimit"), 10_000, 100, 100_000);
            List<ProxyHttpRequestResponse> inspected = history.size() <= limit ? history : history.subList(history.size() - limit, history.size());
            for (ProxyHttpRequestResponse item : inspected) {
                if (Thread.currentThread().isInterrupted()) return;
                if (item.hasResponse()) {
                    try { analyzer.analyze(httpRequestResponse(item.finalRequest(), item.response(), item.annotations()))
                            .ifPresent(c -> catalog.upsert(c, false)); }
                    catch (Exception e) { api.logging().logToError("IDOR history item analysis failed", e); }
                }
            }
            catalog.changed();
            api.logging().logToOutput("IDOR history scan finished: " + inspected.size() + " of " + history.size() + " items inspected.");
        } catch (Exception e) { api.logging().logToError("IDOR history scan failed", e); }
    }

    private int parseLimit(String raw, int fallback, int min, int max) {
        try { return Math.max(min, Math.min(Integer.parseInt(raw), max)); }
        catch (Exception ignored) { return fallback; }
    }

    private void accept(HttpRequestResponse message) {
        try { analyzer.analyze(message).ifPresent(catalog::upsert); }
        catch (Exception e) { api.logging().logToError("IDOR message analysis failed", e); }
    }

    private final class LiveProxyHandler implements ProxyResponseHandler {
        @Override public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
            accept(httpRequestResponse(response.initiatingRequest(), response, response.annotations()));
            return ProxyResponseReceivedAction.continueWith(response, response.annotations());
        }
        @Override public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
            return ProxyResponseToBeSentAction.continueWith(response, response.annotations());
        }
    }

    private final class ProfileMenu implements ContextMenuItemsProvider {
        @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
            Optional<HttpRequestResponse> selected = selectedMessage(event);
            if (selected.isEmpty()) return List.of();
            JMenu root = new JMenu("IDOR Assistant");
            JMenuItem capture = new JMenuItem("Capture as new identity profile");
            capture.addActionListener(e -> panel.capture(selected.get()));
            root.add(capture);
            return List.of(root);
        }

        private Optional<HttpRequestResponse> selectedMessage(ContextMenuEvent event) {
            if (!event.selectedRequestResponses().isEmpty()) return Optional.of(event.selectedRequestResponses().get(0));
            return event.messageEditorRequestResponse().map(MessageEditorHttpRequestResponse::requestResponse);
        }
    }
}
