package com.aadil.webdiagnostic.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body of {@code POST /api/v1/diagnostic}.
 *
 * <p>The POST form exists for privacy: a URL in a query string ends up in proxy logs, browser
 * history and referrer headers on the way to us. In a body it does not.
 *
 * <p>Unknown JSON fields (for example from older clients) are ignored.
 */
public record DiagnosticRequest(
        @NotBlank(message = "url is required")
        @Size(max = 2048, message = "url is too long")
        String url) {
}
