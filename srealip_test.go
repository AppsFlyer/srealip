package srealip

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newHttpRequest(remoteAddr string, xRealIP string, xForwardedFor ...string) *http.Request {
	h := http.Header{
		"X-Real-IP":       []string{xRealIP},
		"X-Forwarded-For": xForwardedFor,
	}

	return &http.Request{
		RemoteAddr: remoteAddr,
		Header:     h,
	}
}

type testStruct struct {
	name string
}

func TestIsPrivate(t *testing.T) {
	publicAddr1 := "144.12.54.87"
	assert.False(t, isPrivateIP(net.ParseIP(publicAddr1)))

	publicAddr2 := "119.14.55.11"
	assert.False(t, isPrivateIP(net.ParseIP(publicAddr2)))

	publicAddr3 := "119.15.55.11"
	assert.False(t, isPrivateIP(net.ParseIP(publicAddr3)))

	localAddr := "127.0.0.0"
	assert.True(t, isPrivateIP(net.ParseIP(localAddr)))

	privateAddr := "192.168.1.1"
	assert.True(t, isPrivateIP(net.ParseIP(privateAddr)))

	invalidAddr := "string"
	assert.False(t, isPrivateIP(net.ParseIP(invalidAddr)))
}

func TestSecureRealIp(t *testing.T) {
	publicAddr1 := "144.12.54.87"
	publicAddr2 := "119.14.55.11"
	publicAddr3 := "119.15.55.11"
	localAddr := "127.0.0.0"
	privateAddr := "192.168.1.1"

	tests := map[string]struct {
		request  *http.Request
		expected string
	}{
		"No X-Forwarded-For":             {request: newHttpRequest(publicAddr1, ""), expected: publicAddr1},
		"X-Forwarded-For - one value":    {request: newHttpRequest(publicAddr1, "", publicAddr2), expected: publicAddr2},
		"multiple X-Forwarded-For":       {request: newHttpRequest(publicAddr3, "", localAddr, publicAddr1, publicAddr2), expected: publicAddr2},
		"Has local X-Forwarded-For":      {request: newHttpRequest(publicAddr3, "", publicAddr1, localAddr), expected: publicAddr1},
		"Has private X-Forwarded-For":    {request: newHttpRequest(publicAddr3, "", publicAddr1, localAddr, privateAddr), expected: publicAddr1},
		"Has X-Real-IP":                  {request: newHttpRequest(publicAddr3, publicAddr2, publicAddr1, localAddr), expected: publicAddr1},
		"not IP X-Forwarded-For":         {request: newHttpRequest(publicAddr3, "", "testString"), expected: publicAddr3},
		"not IP X-Forwarded-For then IP": {request: newHttpRequest(publicAddr3, "", publicAddr1, localAddr, "testString"), expected: publicAddr1},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := SecureRealIP(tc.request); tc.expected != actual {
				t.Errorf("expected %s but got %s", tc.expected, actual)
			}
		})
	}
}
