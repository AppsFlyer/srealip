package srealip

import (
	"net/http"
	"testing"
)

func newHttpRequest(remoteAddr string, xRealIP string, xForwardedFor ...string) *http.Request {
	h := http.Header{}
	h.Set("X-Real-IP", xRealIP)
	for _, address := range xForwardedFor {
		h.Set("X-Forwarded-For", address)
	}

	return &http.Request{
		RemoteAddr: remoteAddr,
		Header:     h,
	}
}

type testStruct struct {
	name     string
	request  *http.Request
	expected string
}

func TestSecureRealIp(t *testing.T) {
	publicAddr1 := "144.12.54.87"
	publicAddr2 := "119.14.55.11"
	publicAddr3 := "119.15.55.11"
	localAddr := "127.0.0.0"

	testData := []testStruct{
		{
			name:     "No X-Forwarded-For",
			request:  newHttpRequest(publicAddr1, ""),
			expected: publicAddr1,
		}, {
			name:     "X-Forwarded-For - one value",
			request:  newHttpRequest(publicAddr1, "", publicAddr2),
			expected: publicAddr2,
		}, {
			name:     "Has multiple X-Forwarded-For",
			request:  newHttpRequest(publicAddr3, "", localAddr, publicAddr1, publicAddr2),
			expected: publicAddr2,
		},
		// TODO - more cases
	}

	for _, v := range testData {
		if actual := SecureRealIP(v.request); v.expected != actual {
			t.Errorf("Test '%s' failed: expected %s but got %s", v.name, v.expected, actual)
		}
	}
}

// TODO -case with multiple Http Header of x-forwared for
