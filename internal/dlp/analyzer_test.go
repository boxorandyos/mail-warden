package dlp

import "testing"

func TestAnalyzeFindsSecretAndSensitiveAttachment(t *testing.T) {
	t.Parallel()
	r := Analyze("api_key=abcdef1234567890 do not share", []string{"prod.key"})
	if !r.Matched {
		t.Fatal("expected dlp match")
	}
	if r.RiskScore < 30 {
		t.Fatalf("expected elevated risk score, got %d", r.RiskScore)
	}
}
