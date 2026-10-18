package com.aadil.webdiagnostic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.security.Security;

@SpringBootApplication
@ConfigurationPropertiesScan
public class WebDiagnosticSystemApplication {

    static {
        // DNS rebinding is prevented structurally, not by caching: every hostname is resolved once by
        // HostResolver, validated, and then connected to by those exact addresses (see PinnedHttpClient).
        // Failures are cached only briefly so a domain that has just been fixed works on retry.
        Security.setProperty("networkaddress.cache.negative.ttl", "1");
    }

    public static void main(String[] args) {
        SpringApplication.run(WebDiagnosticSystemApplication.class, args);
    }
}
