package com.adminsec.idor;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class PassiveSafetyTest {
    @Test void passiveComponentsCannotAccessTheNetworkSender() {
        for (Class<?> type : List.of(DetectionEngine.class, JsonInspector.class, MessageAnalyzer.class))
            for (Field field : type.getDeclaredFields()) {
                assertNotEquals(HttpSender.class, field.getType());
                assertNotEquals(ComparisonOrchestrator.class, field.getType());
            }
    }

    @Test void activeSenderExistsOnlyInTheExplicitOrchestrator() {
        assertTrue(Arrays.stream(ComparisonOrchestrator.class.getDeclaredFields()).anyMatch(field -> field.getType() == HttpSender.class));
    }

    @Test void observedIdsPolicyHasNoEnumerationConfiguration() {
        Set<String> fieldNames = new HashSet<>();
        for (Field field : DetectionEngine.class.getDeclaredFields()) fieldNames.add(field.getName().toLowerCase(Locale.ROOT));
        assertTrue(fieldNames.stream().noneMatch(name -> name.contains("enumerat") || name.contains("bruteforce") || name.contains("neighbor")));
    }
}
