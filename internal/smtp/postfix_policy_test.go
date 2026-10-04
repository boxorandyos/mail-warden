package smtp

import (
	"net"
	"testing"
)

func TestParsePostfixPolicyRequest(t *testing.T) {
	t.Parallel()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("sender=a@example.net\nrecipient=b@company.com\nclient_address=203.0.113.1\n\n"))
	}()

	req, err := parsePostfixPolicyRequest(server)
	if err != nil {
		t.Fatalf("parse policy request: %v", err)
	}
	if req["sender"] != "a@example.net" {
		t.Fatalf("unexpected sender: %s", req["sender"])
	}
	if req["recipient"] != "b@company.com" {
		t.Fatalf("unexpected recipient: %s", req["recipient"])
	}
}
