package com.aadil.webdiagnostic.exception;

/** The target resolves somewhere we refuse to probe (SSRF guard) — maps to HTTP 403. */
public class BlockedTargetException extends RuntimeException {
    public BlockedTargetException(String message) {
        super(message);
    }
}
