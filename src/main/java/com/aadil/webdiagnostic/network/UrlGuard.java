package com.aadil.webdiagnostic.network;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import com.aadil.webdiagnostic.exception.BlockedTargetException;
import com.aadil.webdiagnostic.exception.InvalidTargetException;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;

/**
 * SSRF guard. Everything the server is about to connect to passes through here first, including every
 * hop of a redirect chain. This class judges a URL's syntax and a set of already-resolved addresses; the
 * connection is then made to exactly those addresses, so there is no second lookup to rebind.
 */
@Component
public class UrlGuard {

    private final DiagnosticProperties props;

    public UrlGuard(DiagnosticProperties props) {
        this.props = props;
    }

    /** Scheme / host / port checks. Throws InvalidTargetException (400). */
    public void validateSyntax(URI uri) {
        String scheme = uri.getScheme();
        if (scheme == null
                || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new InvalidTargetException("Only http and https URLs are supported");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new InvalidTargetException("URL does not contain a hostname");
        }
        if (uri.getUserInfo() != null) {
            throw new InvalidTargetException("URLs containing credentials are not supported");
        }

        int port = uri.getPort() == -1
                ? ("https".equalsIgnoreCase(scheme) ? 443 : 80)
                : uri.getPort();

        if (!props.allowedPorts().contains(port)) {
            throw new InvalidTargetException("Port " + port + " is not allowed");
        }
    }

    /** Address checks. Throws BlockedTargetException (403). */
    public void validateAddresses(String host, List<InetAddress> addresses) {
        if (props.allowPrivateAddresses()) {
            return;
        }
        if (addresses.isEmpty()) {
            throw new BlockedTargetException("Host '" + host + "' did not resolve to any address");
        }
        for (InetAddress address : addresses) {
            if (!AddressClassifier.isPublic(address)) {
                throw new BlockedTargetException(
                        "Host '" + host + "' resolves to a non-public address and will not be probed");
            }
        }
    }
}
