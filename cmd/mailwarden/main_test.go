package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()
	limiter := newInMemoryLimiter(time.Minute, 2)
	now := time.Now().UTC()
	if !limiter.Allow("k", now) {
		t.Fatal("first request should be allowed")
	}
	if !limiter.Allow("k", now.Add(1*time.Second)) {
		t.Fatal("second request should be allowed")
	}
	if limiter.Allow("k", now.Add(2*time.Second)) {
		t.Fatal("third request should be denied")
	}
}

func TestClusterNodeAddressValidation(t *testing.T) {
	t.Parallel()
	if !isValidClusterNodeAddress("10.0.0.10:8080") {
		t.Fatal("expected valid cluster node address")
	}
	if isValidClusterNodeAddress("10.0.0.10") {
		t.Fatal("address missing port should be invalid")
	}
}

func TestCallerIPKeyUsesForwardedFor(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "http://example.com", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.10, 198.51.100.2")
	if got := callerIPKey(r); got != "203.0.113.10" {
		t.Fatalf("callerIPKey got %q", got)
	}
}
