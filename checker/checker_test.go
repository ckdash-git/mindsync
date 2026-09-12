package checker

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAllowsCleanText(t *testing.T) {
	res := Check("What's a good way to structure a Go project?", DefaultPolicy())
	if res.Decision != Allow {
		t.Fatalf("expected Allow, got %s (findings: %+v)", res.Decision, res.Findings)
	}
}

func TestMasksEmail(t *testing.T) {
	res := Check("Please email the report to john.doe@example.com", DefaultPolicy())
	if res.Decision != Mask {
		t.Fatalf("expected Mask, got %s", res.Decision)
	}
	if strings.Contains(res.MaskedText, "john.doe@example.com") {
		t.Fatalf("masked text still contains the email: %s", res.MaskedText)
	}
}

func TestKeepsOnPCForAWSKey(t *testing.T) {
	res := Check("Here is my key AKIAABCDEFGHIJKLMNOP for the deploy", DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC, got %s", res.Decision)
	}
}

func TestOrdinaryLongNumberIsNotACard(t *testing.T) {
	// SRV-11: a long reference number that fails Luhn must not be flagged.
	res := Check("Ticket reference: 1234567890123456", DefaultPolicy())
	if res.Decision != Allow {
		t.Fatalf("expected Allow for a non-Luhn-valid number, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestValidCardNumberIsMasked(t *testing.T) {
	// 4111111111111111 is the standard Luhn-valid test Visa number.
	res := Check("My card is 4111111111111111", DefaultPolicy())
	if res.Decision != Mask {
		t.Fatalf("expected Mask for a Luhn-valid card number, got %s", res.Decision)
	}
}

func TestClassifiedTermRefuses(t *testing.T) {
	policy := DefaultPolicy()
	policy.ClassifiedTerms = []string{"Project Nightingale"}
	res := Check("What's the status of Project Nightingale?", policy)
	if res.Decision != Refuse {
		t.Fatalf("expected Refuse for a classified term, got %s", res.Decision)
	}
}

func TestStrictestResultWins(t *testing.T) {
	policy := DefaultPolicy()
	policy.ClassifiedTerms = []string{"Project Nightingale"}
	// Contains both a PII email (-> Mask) and a classified term (-> Refuse).
	res := Check("Send Project Nightingale details to john.doe@example.com", policy)
	if res.Decision != Refuse {
		t.Fatalf("expected Refuse (strictest of Mask/Refuse), got %s", res.Decision)
	}
}

func TestHiddenSecretViaWhitespaceForcesKeepOnPC(t *testing.T) {
	// The AWS key is split with spaces so it's invisible in the raw text but
	// appears once whitespace is stripped (SRV-09/SRV-10).
	hidden := "AKIA ABCD EFGH IJKL MNOP"
	res := Check("Deploy key: "+hidden, DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC for a whitespace-hidden secret, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestHiddenSecretViaBase64ForcesKeepOnPC(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("api_key: sk-verysecretvalue1234567890"))
	res := Check("Config blob: "+encoded, DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC for a base64-hidden secret, got %s (%+v)", res.Decision, res.Findings)
	}
}
