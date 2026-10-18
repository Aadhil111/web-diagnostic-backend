package com.aadil.webdiagnostic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class ExecutorConfig {

    /** Virtual threads: every diagnostic check is blocking I/O, so this scales cheaply. */
    @Bean(destroyMethod = "close")
    public ExecutorService diagnosticExecutor() {
        return Executors.newVirtualThreadPerTaskExecutor();
    }
}
