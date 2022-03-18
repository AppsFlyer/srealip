package srealip

import (
	"net"
	"net/http"
	"strings"
)

// isPrivateIP checks if input IP is under private CIDR blocks.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
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
// Note:
// 1. This IP can be trusted only if your server is behind reverse proxy such as AWS ELB/ALB.
// 2. If all address in `X-Forwarded-For` are private - use http RemoteAddr
func SecureRealIP(r *http.Request) string {
	xForwardedFor := r.Header.Values("X-Forwarded-For")

	// go over xForwardedFor from right to left
	for i := len(xForwardedFor) - 1; i >= 0; i-- {
		value := strings.TrimSpace(xForwardedFor[i])
		realIP := net.ParseIP(value)

		// skip non IP address in xForwardedFor
		if realIP == nil {
			continue
		}

		// skip private addresses
		if isPrivateIP(realIP) {
			continue
		}

		return realIP.String()
	}

	// all address in `X-Forwarded-For` are private - return the rightmost address
	return extractIpFromRemoteAddr(r.RemoteAddr)
}

func NaiveRealIP(r *http.Request) string {
	return "bobo"
}
