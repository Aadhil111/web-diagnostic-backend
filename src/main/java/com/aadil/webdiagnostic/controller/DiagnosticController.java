package com.aadil.webdiagnostic.controller;

import com.aadil.webdiagnostic.dto.DiagnosticRequest;
import com.aadil.webdiagnostic.model.DiagnosticResult;
import com.aadil.webdiagnostic.service.DiagnosticService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class DiagnosticController {

    private final DiagnosticService diagnosticService;

    public DiagnosticController(DiagnosticService diagnosticService) {
        this.diagnosticService = diagnosticService;
    }

    /**
     * Preferred form. The URL travels in the body, so it does not end up in access logs,
     * proxy logs or browser history on the way here.
     */
    @PostMapping("/diagnostic")
    public DiagnosticResult diagnostic(@Valid @RequestBody DiagnosticRequest request) {
        return diagnosticService.diagnose(request.url());
    }

    /** Same thing over GET, for quick testing with curl or a browser address bar. */
    @GetMapping("/diagnostic")
    public DiagnosticResult diagnostic(@RequestParam String url) {
        return diagnosticService.diagnose(url);
    }
}
