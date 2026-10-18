package com.aadil.webdiagnostic.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Liveness endpoint, kept apart from the diagnostic API so it stays trivially cheap and has no
 * dependency on the diagnostic pipeline.
 */
@RestController
@RequestMapping("/api/v1")
public class HealthController {

    /**
     * Cheap liveness ping for the extension and for load balancers. Deliberately exempt from
     * rate limiting (see {@code RateLimitFilter}).
     */
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
