package checker

import "testing"

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

func TestSanitizeForDeliveryWithholdsSecretAnswer(t *testing.T) {
	answer := "Here is the key: AKIAABCDEFGHIJKLMNOP"
	result := Check(answer, DefaultPolicy())
	out, blocked, reason := SanitizeForDelivery(result, answer)
	if !blocked {
		t.Fatal("expected a secret in the answer to block delivery entirely")
	}
	if out != "" {
		t.Fatalf("expected an empty deliverable when blocked, got %q", out)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason when withheld")
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