package com.aadil.webdiagnostic.exception;

/** Too many diagnostics are already running - maps to HTTP 503 so clients back off instead of piling on. */
public class ServiceBusyException extends RuntimeException {
    public ServiceBusyException() {
        super("The service is busy right now. Please try again in a few seconds.");
    }
}
