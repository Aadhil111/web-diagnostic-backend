package com.aadil.webdiagnostic.model;

public record RedirectHop(String url, Integer statusCode, String location) {
}
