package checker

import (
	"strings"
	"testing"
)

func TestSanitizeForDeliveryAllowPassesThrough(t *testing.T) {
	result := Check("the weather is nice today", DefaultPolicy())
	out, blocked, _ := SanitizeForDelivery(result, "the weather is nice today")
	if blocked || out != "the weather is nice today" {
		t.Fatalf("expected unmodified passthrough, got out=%q blocked=%v", out, blocked)
	}
}

func TestSanitizeForDeliveryMasksSensitiveAnswer(t *testing.T) {
	answer := "Sure, contact them at john.doe@example.com"
	result := Check(answer, DefaultPolicy())
	out, blocked, reason := SanitizeForDelivery(result, answer)
	if blocked {
		t.Fatal("expected Mask to NOT block delivery, just redact")
	}
	if out == answer {
		t.Fatal("expected the email to be redacted from the delivered answer")
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason when redaction happens")
	}
}

func TestSanitizeForDeliveryRedactsSecretRatherThanWithholding(t *testing.T) {
	// A secret in a generated ANSWER (as opposed to Refuse-level classified
	// content) redacts and still delivers the rest — full withholding over
	// one flagged span (e.g. a placeholder credential in example code)
	// would destroy an otherwise-good answer for no safety benefit.
	answer := "Here is the key: AKIAABCDEFGHIJKLMNOP"
	result := Check(answer, DefaultPolicy())
	out, blocked, reason := SanitizeForDelivery(result, answer)
	if blocked {
		t.Fatal("expected a secret to be redacted, not fully withheld")
	}
	if out == answer {
		t.Fatal("expected the key to be redacted from the delivered answer")
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason when redaction happens")
	}
}

func TestSanitizeForDeliveryRedactsPlaceholderCredentialInExampleCode(t *testing.T) {
	// The exact real-world case that motivated this change: a coding
	// assistant's example snippet with a placeholder DB connection string
	// must not get the whole (otherwise helpful) answer thrown away.
	answer := `Wire it up like this:` + "\n```go\n" +
		`db, err := postgres.New(ctx, "postgres://user:pw@localhost:5432/db")` + "\n```"
	result := Check(answer, DefaultPolicy())
	out, blocked, _ := SanitizeForDelivery(result, answer)
	if blocked {
		t.Fatal("expected the example code answer to still be delivered, just redacted")
	}
	if out == answer {
		t.Fatal("expected the connection string to be redacted")
	}
	if !strings.Contains(out, "db, err := postgres.New") {
		t.Fatalf("expected the rest of the answer to survive redaction, got: %s", out)
	}
}

func TestSanitizeForDeliveryWithholdsClassifiedAnswer(t *testing.T) {
	policy := DefaultPolicy()
	policy.ClassifiedTerms = []string{"Project Nightingale"}
	answer := "Project Nightingale is on schedule for Q3"
	result := Check(answer, policy)
	out, blocked, _ := SanitizeForDelivery(result, answer)
	if !blocked || out != "" {
		t.Fatalf("expected a classified answer to be fully withheld, got out=%q blocked=%v", out, blocked)
	}
}
