package tier

import (
	"reflect"
	"testing"

	"cigit01.ninjaconnect.co.in/ckdash/mindsync/checker"
)

func TestOrdinaryOnPCChoiceTriesAllThreeInOrder(t *testing.T) {
	got, overridden, _ := Resolve(OnPC, checker.Allow)
	want := []Tier{OnPC, Private, Public}
	if !reflect.DeepEqual(got, want) || overridden {
		t.Fatalf("got %v overridden=%v, want %v not overridden", got, overridden, want)
	}
}

func TestOrdinaryChoosingPrivateSkipsOnPC(t *testing.T) {
	// SRV-47: the user's choice is honoured — starting at Private means
	// on-PC is never tried, even though it's earlier in the fixed order.
	got, _, _ := Resolve(Private, checker.Mask)
	want := []Tier{Private, Public}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOrdinaryChoosingPublicHasNowhereFurtherToFallBack(t *testing.T) {
	got, overridden, _ := Resolve(Public, checker.Allow)
	want := []Tier{Public}
	if !reflect.DeepEqual(got, want) || overridden {
		t.Fatalf("got %v overridden=%v, want %v not overridden", got, overridden, want)
	}
}

func TestSensitiveContentNeverIncludesPublicEvenStartingFromOnPC(t *testing.T) {
	// PC-46's floor: KeepOnPC (a secret) must never reach a public
	// provider, no matter where the escalation starts.
	got, overridden, _ := Resolve(OnPC, checker.KeepOnPC)
	want := []Tier{OnPC, Private}
	if !reflect.DeepEqual(got, want) || overridden {
		t.Fatalf("got %v overridden=%v, want %v not overridden (on-pc doesn't need an override, it's already safe)", got, overridden, want)
	}
}

func TestSensitiveContentChoosingPublicIsOverriddenToPrivate(t *testing.T) {
	// SRV-49: the check may only move the choice to something SAFER.
	// SRV-50: the caller must be told this happened and why.
	got, overridden, reason := Resolve(Public, checker.KeepOnPC)
	want := []Tier{Private}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !overridden {
		t.Fatal("expected the public choice to be flagged as overridden")
	}
	if reason == "" {
		t.Fatal("expected a non-empty plain-words reason (SRV-50)")
	}
}

func TestSensitiveContentChoosingPrivateNeedsNoOverride(t *testing.T) {
	// Private is already a safe enough place for sensitive content —
	// SRV-49 only overrides when the CHOSEN place isn't safe enough, not
	// unconditionally.
	got, overridden, _ := Resolve(Private, checker.KeepOnPC)
	want := []Tier{Private}
	if !reflect.DeepEqual(got, want) || overridden {
		t.Fatalf("got %v overridden=%v, want %v not overridden", got, overridden, want)
	}
}

func TestEmptyChoiceDefaultsToOnPC(t *testing.T) {
	got, _, _ := Resolve("", checker.Allow)
	if len(got) == 0 || got[0] != OnPC {
		t.Fatalf("expected default choice to start at on-pc, got %v", got)
	}
}

func TestNeverOverriddenTowardsRiskier(t *testing.T) {
	// SRV-49's other half: ordinary content choosing a less-safe-looking
	// tier is never pushed toward something SAFER than what was asked for
	// — overriding only ever happens because the CHOSEN place is unsafe
	// for THIS content, never as an unprompted "upgrade".
	got, overridden, _ := Resolve(Public, checker.Allow)
	if overridden {
		t.Fatal("ordinary content choosing Public must not be overridden — Public is safe enough for it")
	}
	if len(got) != 1 || got[0] != Public {
		t.Fatalf("expected the choice honoured as-is, got %v", got)
	}
}
