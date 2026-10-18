package com.aadil.webdiagnostic.security;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import com.aadil.webdiagnostic.security.filter.RateLimitFilter;
import com.aadil.webdiagnostic.security.filter.RequestIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * Spring Security is used here for what it is good at - one well-ordered filter chain, CORS and
 * hardened response headers - and for nothing else. There is no authentication, no user, no session
 * and no authorization rule: the API is public and every request is permitted.
 *
 * <p>Filter order, outermost first:
 * <ol>
 *   <li>{@link RequestIdFilter}: every response, including CORS refusals and 429s, carries an id;</li>
 *   <li>Spring Security's {@link CorsFilter}: answers browser preflights itself, so a preflight never
 *       spends rate-limit budget, and puts CORS headers on every later response, so a page can read a 429;</li>
 *   <li>{@link RateLimitFilter}.</li>
 * </ol>
 *
 * <p>CSRF protection is switched off deliberately: it defends cookie-based sessions, and this API has
 * neither cookies nor sessions nor credentials ({@code allowCredentials} is false).
 */
@Configuration
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    /**
     * This API has no users. Declaring an (empty) UserDetailsService makes Spring Boot's default-user
     * auto-configuration back off, so it no longer logs "Using generated security password". It works on any
     * Boot version, unlike excluding the auto-configuration by class name (Boot 4 moved that class).
     */
    @Bean
    public UserDetailsService noUsers() {
        return new InMemoryUserDetailsManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, DiagnosticProperties props) throws Exception {
        http
                .cors(Customizer.withDefaults())      // picks up the CorsConfigurationSource bean below
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(new RequestIdFilter(), CorsFilter.class)
                .addFilterAfter(new RateLimitFilter(props), CorsFilter.class);
        return http.build();
    }

    /**
     * Only the origins listed in {@code diagnostic.cors}: the configured extension ids and, in
     * development only, localhost. In the prod profile at least one extension id is required, so a
     * forgotten setting stops the deployment instead of silently widening or closing access.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(DiagnosticProperties props, Environment environment) {
        DiagnosticProperties.Cors settings = props.cors();

        if (environment.acceptsProfiles(Profiles.of("prod"))) {
            if (settings.extensionIds().isEmpty() && settings.allowedOrigins().isEmpty()) {
                throw new IllegalStateException(
                        "The prod profile requires diagnostic.cors.extension-ids "
                                + "(environment variable DIAGNOSTIC_CORS_EXTENSION_IDS) to be set to your Chrome extension id, "
                                + "or diagnostic.cors.allowed-origins (DIAGNOSTIC_CORS_ALLOWED_ORIGINS) to your website origin");
            }
            if (settings.allowAnyExtension()) {
                throw new IllegalStateException("diagnostic.cors.allow-any-extension must not be enabled in the prod profile");
            }
            if (settings.allowLocalhost()) {
                throw new IllegalStateException("diagnostic.cors.allow-localhost must not be enabled in the prod profile");
            }
            if (props.allowPrivateAddresses()) {
                throw new IllegalStateException(
                        "diagnostic.allow-private-addresses must not be enabled in the prod profile: it switches the SSRF guard off");
            }
        }

        List<String> origins = settings.allowedOriginPatterns();
        if (origins.isEmpty()) {
            log.warn("No CORS origin is allowed: browser pages and extensions cannot call this API. "
                    + "Set diagnostic.cors.extension-ids or diagnostic.cors.allowed-origins.");
        }

        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOriginPatterns(origins);
        cors.setAllowedMethods(List.of(HttpMethod.GET.name(), HttpMethod.POST.name()));
        cors.setAllowedHeaders(List.of("Content-Type", RequestIdFilter.HEADER));
        // Without this the page can't read them from JavaScript and can't back off politely.
        cors.setExposedHeaders(List.of(RequestIdFilter.HEADER, "Retry-After",
                "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
        cors.setAllowCredentials(false);
        cors.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", cors);
        return source;
    }
}
