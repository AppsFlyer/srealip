package srealip

import (
	"net"
	"net/http"
	"strings"
)

// isPrivateIP checks if input IP is under private CIDR blocks.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || isInSharedAddressSpace(ip)
}

// isInSharedAddressSpace reports whether ip is in the shared address space, according to
// RFC 6598- IANA-Reserved IPv4 Prefix for Shared Address Space
func isInSharedAddressSpace(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Following RFC 6598. Shared Address Space which says:
		//   The Internet Assigned Numbers Authority (IANA) has reserved the
		//   following block of IP address space for shared internets:
		//     100.64.0.0    -   100.127.255.255  (100.64/10 prefix)
		return ip4[0] == 100 && ip4[1]&0xc0 == 64
	}
	return false
}

// extractIpFromRemoteAddr extracts clean IP - without port and spaces
func extractIpFromRemoteAddr(remoteAddr string) string {
	address := strings.TrimSpace(remoteAddr)

	var remoteAddrClean string

	// If there are colon in remote address, remove the port number
	// otherwise, return remote address as is
	if strings.ContainsRune(address, ':') {
		remoteAddrClean, _, _ = net.SplitHostPort(address)
	} else {
		remoteAddrClean = address
	}

	return remoteAddrClean
}

// SecureRealIP returns the trusted non-private real IP address from input request.
// Note: This IP can be trusted only if your server is behind reverse proxy such as AWS ELB/ALB.
func SecureRealIP(r *http.Request) string {
	xForwardedFor := r.Header.Values("X-Forwarded-For")

	// go over xForwardedFor from right to left, return the rightmost non private IP address
	for i := len(xForwardedFor) - 1; i >= 0; i-- {
		value := strings.TrimSpace(xForwardedFor[i])
		realIP := net.ParseIP(value)

		// skip non IP strings or private IP addresses in xForwardedFor
		if realIP == nil || isPrivateIP(realIP) {
			continue
		}

		return realIP.String()
	}

	// all address in `X-Forwarded-For` are private or invaid - return HTTP RemoteAddr
	return extractIpFromRemoteAddr(r.RemoteAddr)
}

// NaiveRealIP returns the most real non-private IP address ("closest to client") from input request.
// Note: This IP can be spoofed by malicious sender, so avoid using it for security purposes
func NaiveRealIP(r *http.Request) string {
	// X-Real-IP header should contain only one value
	xRealIPHeader := r.Header.Get("X-Real-IP")
	xRealIP := net.ParseIP(xRealIPHeader)

	if xRealIP != nil && !isPrivateIP(xRealIP) {
		return xRealIPHeader
	}

	xForwardedFor := r.Header.Values("X-Forwarded-For")
	// go over xForwardedFor from left to right, return the leftmost non private IP address
	for i := 0; i < len(xForwardedFor); i++ {
		value := strings.TrimSpace(xForwardedFor[i])
		realIP := net.ParseIP(value)

		// skip non IP strings or private IP addresses in xForwardedFor
		if realIP == nil || isPrivateIP(realIP) {
			continue
		}

		return realIP.String()
	}

	// all address in `X-Forwarded-For` and 'X-Real-IP' are private or empty - return HTTP RemoteAddr
	return extractIpFromRemoteAddr(r.RemoteAddr)
}
