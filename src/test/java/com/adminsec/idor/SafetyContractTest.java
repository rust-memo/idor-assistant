package com.adminsec.idor;

import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class SafetyContractTest {
    @Test void passiveClassesContainNoRequestSender() throws Exception {
        String analyzer = Files.readString(Path.of("src/main/java/com/adminsec/idor/MessageAnalyzer.java"));
        String detector = Files.readString(Path.of("src/main/java/com/adminsec/idor/DetectionEngine.java"));
        assertFalse(analyzer.contains("sendRequest("));
        assertFalse(detector.contains("sendRequest("));
    }

    @Test void comparisonHardBlocksOutOfScopeAndMutationsRequireUiConfirmation() throws Exception {
        String service = Files.readString(Path.of("src/main/java/com/adminsec/idor/ComparisonService.java"));
        String panel = Files.readString(Path.of("src/main/java/com/adminsec/idor/IdorPanel.java"));
        assertTrue(service.contains("!original.isInScope()"));
        assertTrue(panel.contains("Confirm state-changing request"));
        assertTrue(panel.contains("showConfirmDialog"));
        assertTrue(service.contains("IdentityProfile.withoutAuthentication(original)"));
        assertTrue(service.contains("!original.isInScope()"));
    }

    @Test void historyScannerStopsWhenTheExtensionUnloads() throws Exception {
        String extension = Files.readString(Path.of("src/main/java/com/adminsec/idor/IdorAssistantExtension.java"));
        assertTrue(extension.contains("registerUnloadingHandler"));
        assertTrue(extension.contains("scanner.interrupt()"));
        assertTrue(extension.contains("Thread.currentThread().isInterrupted()"));
    }
}
