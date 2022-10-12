package srealip

import "net"

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
