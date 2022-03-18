package srealip

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newHttpRequest(remoteAddr string, xRealIP string, xForwardedFor ...string) *http.Request {
	h := http.Header{
		"X-Forwarded-For": xForwardedFor,
	}
	h.Set("X-Real-IP", xRealIP)

	return &http.Request{
		RemoteAddr: remoteAddr,
		Header:     h,
	}
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

	emptyAddr := ""
	assert.False(t, isPrivateIP(net.ParseIP(emptyAddr)))
}

func TestSecureRealIp(t *testing.T) {
	publicAddr1 := "144.12.54.87"
	publicAddr2 := "119.14.55.11"
	publicAddr3 := "119.15.55.11"
	localAddr := "127.0.0.0"
	privateAddr := "192.168.1.1"
	publicAddr1WithPort := fmt.Sprintf("%s:%d", publicAddr1, 80)
	invalidAddr := "invalidStr"

	tests := map[string]struct {
		request  *http.Request
		expected string
	}{
		"No X-Forwarded-For":              {request: newHttpRequest(publicAddr1, ""), expected: publicAddr1},
		"X-Forwarded-For - one value":     {request: newHttpRequest(publicAddr1, "", publicAddr2), expected: publicAddr2},
		"multiple X-Forwarded-For":        {request: newHttpRequest(publicAddr3, "", localAddr, publicAddr1, publicAddr2), expected: publicAddr2},
		"Has local X-Forwarded-For":       {request: newHttpRequest(publicAddr3, "", publicAddr1, localAddr), expected: publicAddr1},
		"Has private X-Forwarded-For":     {request: newHttpRequest(publicAddr3, "", publicAddr1, localAddr, privateAddr), expected: publicAddr1},
		"Has X-Real-IP":                   {request: newHttpRequest(publicAddr3, publicAddr2, publicAddr1, localAddr), expected: publicAddr1},
		"not IP X-Forwarded-For":          {request: newHttpRequest(publicAddr3, "", invalidAddr), expected: publicAddr3},
		"not + vallid IP X-Forwarded-For": {request: newHttpRequest(publicAddr3, "", publicAddr2, privateAddr, invalidAddr), expected: publicAddr2},
		"not IP X-Forwarded-For then IP":  {request: newHttpRequest(publicAddr3, "", publicAddr1, localAddr, invalidAddr), expected: publicAddr1},
		"RemoteAddr with port":            {request: newHttpRequest(publicAddr1WithPort, "", localAddr, invalidAddr), expected: publicAddr1},
		"invalid at all header":           {request: newHttpRequest(invalidAddr, invalidAddr, invalidAddr), expected: invalidAddr},
		"empty IP at all header":          {request: newHttpRequest("", ""), expected: ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := SecureRealIP(tc.request); tc.expected != actual {
				t.Errorf("expected %s but got %s", tc.expected, actual)
			}
		})
	}
}

func TestNaiveRealIp(t *testing.T) {
	publicAddr1 := "144.12.54.87"
	publicAddr2 := "119.14.55.11"
	publicAddr3 := "119.15.55.11"
	publicAddr4 := "119.16.55.11"
	localAddr := "127.0.0.0"
	privateAddr := "192.168.1.1"
	invalidAddr := "invalidStr"
	publicAddr1WithPort := fmt.Sprintf("%s:%d", publicAddr1, 80)

	tests := map[string]struct {
		request  *http.Request
		expected string
	}{
		"No X-Forwarded-For":              {request: newHttpRequest(publicAddr1, ""), expected: publicAddr1},
		"X-Forwarded-For - one value":     {request: newHttpRequest(publicAddr1, "", publicAddr2), expected: publicAddr2},
		"multiple X-Forwarded-For":        {request: newHttpRequest(publicAddr3, "", localAddr, publicAddr1, publicAddr2), expected: publicAddr1},
		"Has private X-Forwarded-For":     {request: newHttpRequest(publicAddr3, "", privateAddr, publicAddr1, localAddr), expected: publicAddr1},
		"not IP X-Forwarded-For":          {request: newHttpRequest(publicAddr3, "", invalidAddr), expected: publicAddr3},
		"not + vallid IP X-Forwarded-For": {request: newHttpRequest(publicAddr3, "", privateAddr, publicAddr2, invalidAddr), expected: publicAddr2},
		"not IP X-Forwarded-For then IP":  {request: newHttpRequest(publicAddr3, "", localAddr, invalidAddr, publicAddr1), expected: publicAddr1},
		"Has X-Real-IP":                   {request: newHttpRequest(publicAddr3, publicAddr2, publicAddr1, localAddr), expected: publicAddr2},
		"Private X-Real-IP":               {request: newHttpRequest(publicAddr3, privateAddr, localAddr, publicAddr1), expected: publicAddr1},
		"Private Headers":                 {request: newHttpRequest(publicAddr3, privateAddr, localAddr, privateAddr), expected: publicAddr3},
		"Invalid X-Real-IP":               {request: newHttpRequest(publicAddr3, invalidAddr, publicAddr1), expected: publicAddr1},
		"Invalid Headers":                 {request: newHttpRequest(publicAddr3, invalidAddr, invalidAddr), expected: publicAddr3},
		"RemoteAddr with port":            {request: newHttpRequest(publicAddr1WithPort, "", localAddr, invalidAddr), expected: publicAddr1},
		"empty IP at all header":          {request: newHttpRequest("", ""), expected: ""},
		"invalid at all header":           {request: newHttpRequest(invalidAddr, invalidAddr, invalidAddr), expected: invalidAddr},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if actual := NaiveRealIP(tc.request); tc.expected != actual {
				t.Errorf("expected %s but got %s", tc.expected, actual)
			}
		})
	}

	// Test multiple "X-Real-IP"
	req := newHttpRequest(publicAddr3, publicAddr2, publicAddr1)
	req.Header.Add("X-Real-IP", publicAddr4)
	assert.Equal(t, publicAddr2, NaiveRealIP(req))

	// Test multiple "X-Real-IP", with invalid value as second
	// NaiveRealIP should only look on the first value
	req = newHttpRequest(publicAddr3, publicAddr2, publicAddr1)
	req.Header.Add("X-Real-IP", invalidAddr)
	assert.Equal(t, publicAddr2, NaiveRealIP(req))

	// Test multiple "X-Real-IP", with invalid value as first
	req = newHttpRequest(publicAddr3, invalidAddr, publicAddr1)
	req.Header.Add("X-Real-IP", publicAddr2)
	assert.Equal(t, publicAddr1, NaiveRealIP(req))
}
