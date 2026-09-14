package checker

import (
	"encoding/json"
	"os"
	"testing"
)

// conformanceCase mirrors the shared JSON corpus format from the
// e-Jan aigw engine (corpus.json, attacks.json) — same shape, so
// these files can be dropped in unmodified as they're updated on
// that side. action uses their vocabulary (allow/redact/local/block);
// wantDecision translates it to ours.
type conformanceCase struct {
	Name   string   `json:"name"`
	Prompt string   `json:"prompt"`
	Action string   `json:"action"`
	Labels []string `json:"labels"`
}

type conformanceFile struct {
	Cases []conformanceCase `json:"cases"`
}

func actionToDecision(t *testing.T, action string) Decision {
	t.Helper()
	switch action {
	case "allow":
		return Allow
	case "redact":
		return Mask
	case "local":
		return KeepOnPC
	case "block":
		return Refuse
	default:
		t.Fatalf("unknown action in corpus: %q", action)
		return Allow
	}
}

// runConformanceFile loads one shared corpus file and checks every case
// against OUR checker, reporting each failure individually (not just a
// pass/fail count) so a run tells you exactly which specific behavior is
// missing or wrong, not just that something is.
func runConformanceFile(t *testing.T, path string) (passed, failed int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var f conformanceFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	for _, c := range f.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			want := actionToDecision(t, c.Action)
			result := Check(c.Prompt, DefaultPolicy())
			if result.Decision != want {
				failed++
				t.Errorf("prompt %q: want %s, got %s", c.Prompt, want, result.Decision)
				return
			}
			passed++
		})
	}
	return passed, failed
}

func TestConformanceCorpus(t *testing.T) {
	runConformanceFile(t, "testdata/corpus.json")
}

func TestConformanceAttacks(t *testing.T) {
	// Expected, going in: this file tests prompt-injection detection
	// (instruction overrides, role hijacks, exfiltration requests) —
	// a category our checker has never implemented. Every "block" case
	// here is expected to fail today. That's the point of running it:
	// a concrete, named list of exactly what's missing, not a guess.
	runConformanceFile(t, "testdata/attacks.json")
}