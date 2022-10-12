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
