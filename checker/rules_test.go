package checker

import "testing"

func TestGitHubTokenKeepsOnPC(t *testing.T) {
	res := Check("Use this token: ghp_16C7e42F292c6912E7710c838347Ae178B4a", DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC for a GitHub token, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestSlackWebhookKeepsOnPC(t *testing.T) {
	res := Check("Post to https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC for a Slack webhook, got %s", res.Decision)
	}
}

func TestStripeKeyKeepsOnPC(t *testing.T) {
	res := Check("sk_live_51H8xamplekeyabcdefghijklmno", DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC for a Stripe secret key, got %s", res.Decision)
	}
}

func TestDBConnectionStringWithPasswordKeepsOnPC(t *testing.T) {
	res := Check("Connect using postgres://admin:sup3rSecret@db.internal:5432/prod", DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC for a connection string with a password, got %s", res.Decision)
	}
}

func TestValidSSNIsMasked(t *testing.T) {
	res := Check("His SSN is 219-09-9999 for the background check", DefaultPolicy())
	if res.Decision != Mask {
		t.Fatalf("expected Mask for a plausible SSN, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestObviouslyFakeSSNIsAllowed(t *testing.T) {
	// Area number 000 is never issued — this is what ssnLooksValid rejects.
	res := Check("Example format: 000-12-3456", DefaultPolicy())
	if res.Decision != Allow {
		t.Fatalf("expected Allow for a format-only fake SSN, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestValidIBANIsMasked(t *testing.T) {
	// GB29 NWBK 6016 1331 9268 19 is the standard published IBAN example
	// and passes the mod-97 checksum.
	res := Check("Wire to GB29NWBK60161331926819 please", DefaultPolicy())
	if res.Decision != Mask {
		t.Fatalf("expected Mask for a checksum-valid IBAN, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestChecksumInvalidIBANLookalikeIsAllowed(t *testing.T) {
	// Same shape as a real IBAN, wrong checksum digits — should NOT confirm.
	res := Check("Reference code GB00AAAA00000000000000", DefaultPolicy())
	if res.Decision != Allow {
		t.Fatalf("expected Allow for a checksum-invalid IBAN lookalike, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestHighEntropyFallbackCatchesUnknownFormat(t *testing.T) {
	// Not shaped like any known provider token, but has the entropy profile
	// of a real credential — this is exactly what the fallback is for.
	res := Check("internal_token=Xk9mQz3vR8pL2wN7tY4hB6jF1cA5sD0eG", DefaultPolicy())
	if res.Decision != KeepOnPC {
		t.Fatalf("expected KeepOnPC from the entropy fallback, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestOrdinaryProseDoesNotTriggerEntropyFallback(t *testing.T) {
	res := Check("The quarterly report shows revenue increased significantly across every region this year", DefaultPolicy())
	if res.Decision != Allow {
		t.Fatalf("expected Allow for ordinary prose, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestWhitespaceStrippedProseDoesNotTriggerEntropyFallback(t *testing.T) {
	// This is the case entropy.go specifically warns about: run ordinary
	// words together and they can look "high entropy" by character
	// frequency alone. Confirms the whitespace-stripped view is exempted.
	res := Check("this is a fairly long sentence without any real secrets in it at all today", DefaultPolicy())
	if res.Decision != Allow {
		t.Fatalf("expected Allow — entropy fallback must not run on the whitespace-stripped view, got %s (%+v)", res.Decision, res.Findings)
	}
}

func TestFindingsAreDeduplicated(t *testing.T) {
	res := Check("Contact john.doe@example.com for details", DefaultPolicy())
	count := 0
	for _, f := range res.Findings {
		if f.Label == "email" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 deduplicated email finding, got %d (%+v)", count, res.Findings)
	}
}

func TestIBANChecksumValidatorDirectly(t *testing.T) {
	if !ibanChecksumValid("GB29NWBK60161331926819") {
		t.Fatal("expected the standard example IBAN to pass mod-97 validation")
	}
	if ibanChecksumValid("GB00AAAA00000000000000") {
		t.Fatal("expected a checksum-invalid IBAN to fail validation")
	}
}

func TestShannonEntropyMonotonic(t *testing.T) {
	low := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaa")
	high := shannonEntropy("Xk9mQz3vR8pL2wN7tY4hB6jF")
	if low >= high {
		t.Fatalf("expected repeated-character string to have lower entropy than a random-looking one: low=%f high=%f", low, high)
	}
}
