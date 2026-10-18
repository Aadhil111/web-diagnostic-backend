package com.aadil.webdiagnostic.exception;

/** The submitted URL is malformed or unsupported — maps to HTTP 400. */
public class InvalidTargetException extends RuntimeException {
    public InvalidTargetException(String message) {
        super(message);
    }
}
