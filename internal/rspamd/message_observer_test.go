package rspamd

import "testing"

func TestExtractURLObservations(t *testing.T) {
	t.Parallel()

	raw := []byte("hello https://example.com/path and https://evil.test/login")
	obs := ExtractURLObservations(raw, true, "high")
	if len(obs) != 2 {
		t.Fatalf("expected 2 url observations, got %d", len(obs))
	}
	if obs[0].Domain == "" || obs[1].Domain == "" {
		t.Fatal("expected parsed domains")
	}
}

func TestExtractAttachmentObservations(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@example.com\r\n" +
		"To: b@example.com\r\n" +
		"Subject: test\r\n" +
		"Content-Type: multipart/mixed; boundary=frontier\r\n\r\n" +
		"--frontier\r\n" +
		"Content-Type: text/plain\r\n\r\nhello\r\n" +
		"--frontier\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"invoice.exe\"\r\n\r\n" +
		"abc123\r\n" +
		"--frontier--\r\n")

	attachments := ExtractAttachmentObservations(raw)
	if len(attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(attachments))
	}
	if !attachments[0].Suspicious {
		t.Fatal("expected suspicious attachment")
	}
}
