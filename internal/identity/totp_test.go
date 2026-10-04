package identity

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	code := totpAt(raw, now.Unix()/30)
	if !ValidateTOTP(secret, code, now) {
		t.Fatal("expected generated code to validate")
	}
	if ValidateTOTP(secret, "000000", now.Add(2*time.Hour)) && code == "000000" {
		t.Fatal("unexpected fixed code")
	}
}
