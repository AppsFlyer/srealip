# srealip (Secure Real IP)

[![Actions Status](https://github.com/AppsFlyer/srealip/workflows/srealip/badge.svg?branch=main)](https://github.com/AppsFlyer/srealip/actions)
[![Godocs](https://img.shields.io/badge/golang-documentation-blue.svg)](https://pkg.go.dev/github.com/AppsFlyer/srealip)

Go package for securely extracting HTTP client's real public IP for rate limit, IP limit or logging on HTTP Server.

(Update - see this [Blog by Adam Pritchard](https://adam-p.ca/blog/2022/03/x-forwarded-for/?s=09) for comprehensive analysis of HTTP headers and security)

The library provides two methods for extracting the IP address from HTTP Request:

- **SecureRealIP** - returns the trusted non-private real IP address from input request. This IP can be trusted only if your HTTP server is behind a reverse proxy such as [AWS ELB/ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html), [Azure Front Door](https://docs.microsoft.com/en-us/azure/frontdoor/afront-door-http-headers-protocol) or [Google Load Balancer](https://cloud.google.com/load-balancing/docs/https#x-forwarded-for_header). It can be used for security use cases (Rate Limit, IP Limit, etc..).

- **NaiveRealIP** - returns the most real non-private IP address ("closest to client") from input request. This IP can be spoofed by malicious sender, so avoid using it for security purposes (only for logging or troubleshooting).

## Example

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/AppsFlyer/srealip"
)

func Handle(r *http.Request) {
	naiveIP := srealip.NaiveRealIP(r)

	fmt.Printf("Client's IP for logging / troubleshooting: %s\n", naiveIP)

	secureIP := srealip.SecureRealIP(r)
	fmt.Printf("Client's IP for rate / ip limit: %s\n", secureIP)
}
```
