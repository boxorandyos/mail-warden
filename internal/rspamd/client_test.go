package rspamd

import "testing"

func TestNormalizeDetectsSecuritySignals(t *testing.T) {
	t.Parallel()

	raw := rawRspamdResponse{}
	raw.Default.Score = 12.3
	raw.Default.RequiredScore = 8
	raw.Default.Action = "add header"
	raw.Default.Symbols = map[string]rawRspamdSymbolRef{
		"MALICIOUS_URL": {},
		"CLAM_VIRUS":    {},
	}

	out := normalize(raw)
	if !out.MaliciousURL {
		t.Fatal("expected malicious url detection")
	}
	if !out.MalwareDetected {
		t.Fatal("expected malware detection")
	}
	if !out.Spam {
		t.Fatal("expected spam classification by score")
	}
}
