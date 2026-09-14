package checker

import (
	"math"
	"regexp"
)

// highEntropyCandidateRe finds contiguous alphanumeric runs long enough to
// plausibly be a credential in an unrecognized format. Deliberately
// excludes '/', '+', '.', '-' etc so ordinary URLs and file paths don't get
// swept in as one long "token" just because they lack spaces.
var highEntropyCandidateRe = regexp.MustCompile(`[A-Za-z0-9]{24,}`)

// shannonEntropy is the standard order-0 entropy calculation (bits per
// character) used by detect-secrets and gitleaks' own entropy plugin to
// flag high-entropy strings that don't match any known provider format.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int, len(s))
	for _, r := range s {
		counts[r]++
	}
	length := float64(len(s))
	var entropy float64
	for _, c := range counts {
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isHexOnly(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func hasLetterAndDigit(s string) bool {
	var hasLetter, hasDigit bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		}
	}
	return hasLetter && hasDigit
}

// scanHighEntropy is the fallback for secrets that don't match any known
// provider format in rules_secrets.go — the same reason gitleaks and
// detect-secrets both ship an entropy plugin alongside their pattern
// tables: new credential formats appear faster than anyone maintains a
// pattern list for them.
//
// Deliberately NOT run on the whitespace-stripped or invisible-stripped
// views: those merge ordinary prose into long fake "tokens" once spaces are
// removed, and ordinary English text sits close enough to these entropy
// thresholds to false-positive constantly. Evasion of a *known* secret
// format is still caught in those views via the regular rules; entropy
// scanning only makes sense on text that was already contiguous.
func scanHighEntropy(text string, view View) []Finding {
	var findings []Finding
	for _, tok := range highEntropyCandidateRe.FindAllString(text, -1) {
		if !hasLetterAndDigit(tok) {
			// Excludes plain words (no digit) and plain numbers (no
			// letter, and already handled by the card/phone/SSN checks).
			continue
		}
		if isHexOnly(tok) && (len(tok) == 40 || len(tok) == 64) {
			// A git commit SHA (40 hex chars, SHA-1) or a SHA-256 digest
			// (64 hex chars) — both extremely common in ordinary
			// engineering conversation (build hashes, commit refs) and
			// not secrets. A real hex-encoded secret happening to land
			// on exactly one of these two lengths is rare enough that
			// excluding them outright beats flagging every commit hash
			// anyone ever pastes.
			continue
		}
		threshold := 4.0 // mixed alnum, ~62-symbol alphabet
		if isHexOnly(tok) {
			threshold = 3.0 // smaller alphabet, needs a lower bar
		}
		if shannonEntropy(tok) >= threshold {
			findings = append(findings, Finding{Kind: KindSecret, Label: "high_entropy_string", View: view, Span: tok})
		}
	}
	return findings
}
