package com.aadil.webdiagnostic.network;

import java.net.Inet4Address;
import java.net.InetAddress;

/**
 * Decides whether an IP address is a public, globally routable unicast address.
 *
 * <p>The rule is an allow-list for IPv6 (only {@code 2000::/3}, minus the special-use blocks inside it)
 * and a deny-list of IANA special-purpose blocks for IPv4. Addresses that merely <em>wrap</em> an IPv4
 * address (IPv4-mapped {@code ::ffff:a.b.c.d}, NAT64 {@code 64:ff9b::/96}, 6to4 {@code 2002::/16}) are
 * judged by the IPv4 address inside them, so {@code ::ffff:127.0.0.1} cannot slip through as "IPv6".
 */
public final class AddressClassifier {

    private AddressClassifier() {
    }

    public static boolean isPublic(InetAddress address) {
        byte[] b = address.getAddress();
        if (address instanceof Inet4Address || b.length == 4) {
            return isPublicIpv4(b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF, b[3] & 0xFF);
        }
        return b.length == 16 && isPublicIpv6(b);
    }

    private static boolean isPublicIpv4(int a, int b, int c, int d) {
        if (a == 0) return false;                                  // 0.0.0.0/8 "this network"
        if (a == 10) return false;                                 // 10.0.0.0/8 private
        if (a == 100 && b >= 64 && b <= 127) return false;        // 100.64.0.0/10 carrier-grade NAT
        if (a == 127) return false;                                // 127.0.0.0/8 loopback
        if (a == 169 && b == 254) return false;                    // 169.254.0.0/16 link-local, cloud metadata
        if (a == 172 && b >= 16 && b <= 31) return false;         // 172.16.0.0/12 private
        if (a == 192 && b == 0 && c == 0) return false;            // 192.0.0.0/24 IETF protocol assignments
        if (a == 192 && b == 0 && c == 2) return false;            // 192.0.2.0/24 documentation
        if (a == 192 && b == 88 && c == 99) return false;          // 192.88.99.0/24 6to4 relay anycast
        if (a == 192 && b == 168) return false;                    // 192.168.0.0/16 private
        if (a == 198 && (b == 18 || b == 19)) return false;        // 198.18.0.0/15 benchmarking
        if (a == 198 && b == 51 && c == 100) return false;         // 198.51.100.0/24 documentation
        if (a == 203 && b == 0 && c == 113) return false;          // 203.0.113.0/24 documentation
        return a < 224;                                            // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved + broadcast
    }

    private static boolean isPublicIpv6(byte[] b) {
        // ::ffff:0:0/96 IPv4-mapped (Java normally turns these into Inet4Address, but never rely on it)
        if (zeros(b, 0, 10) && (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF) {
            return embeddedIpv4IsPublic(b, 12);
        }
        // 64:ff9b::/96 NAT64: the real destination is the IPv4 address in the last 32 bits
        if (b[0] == 0x00 && b[1] == 0x64 && (b[2] & 0xFF) == 0xFF && (b[3] & 0xFF) == 0x9B && zeros(b, 4, 12)) {
            return embeddedIpv4IsPublic(b, 12);
        }
        // Everything outside 2000::/3 (loopback, unspecified, ULA fc00::/7, link-local fe80::/10,
        // site-local fec0::/10, multicast ff00::/8, discard 100::/64, IPv4-compatible ::/96, ...)
        if ((b[0] & 0xE0) != 0x20) {
            return false;
        }
        int w0 = ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
        int w1 = ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);

        if (w0 == 0x2001 && w1 < 0x0200) return false;             // 2001::/23 IETF protocol assignments (Teredo, ORCHID, ...)
        if (w0 == 0x2001 && w1 == 0x0DB8) return false;            // 2001:db8::/32 documentation
        if (w0 == 0x2002) return embeddedIpv4IsPublic(b, 2);       // 2002::/16 6to4: IPv4 address in bits 16-47
        if (w0 == 0x3FFF && (w1 & 0xF000) == 0) return false;      // 3fff::/20 documentation (RFC 9637)
        return true;
    }

    private static boolean embeddedIpv4IsPublic(byte[] b, int offset) {
        return isPublicIpv4(b[offset] & 0xFF, b[offset + 1] & 0xFF, b[offset + 2] & 0xFF, b[offset + 3] & 0xFF);
    }

    private static boolean zeros(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return true;
    }
}
