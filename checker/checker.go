// Package checker is the single choke point every prompt passes through
// before it goes anywhere (SRV-06). It never returns anything other than
// one of the four results in SRV-07, and it applies the "strictest result
// wins" rule from SRV-12.
//
// Detection is split across three layers, each catching what the last one
// can't:
//  1. Known-format rules (rules_secrets.go, rules_pii.go) — provider-specific
//     patterns (AWS, GitHub, Slack, Stripe, ...) plus checksum-confirmed PII
//     (Luhn for cards, SSA ranges for SSNs, mod-97 for IBANs) per SRV-11.
//  2. Entropy fallback (entropy.go) — catches secrets in formats nobody
//     wrote a pattern for yet, the same reason gitleaks and detect-secrets
//     both ship an entropy plugin alongside their pattern tables.
//  3. Evasion views (SRV-09) — whitespace-stripped, invisible-character-
//     stripped, and base64-decoded readings of the same text, so a secret
//     split with spaces or hidden in an encoded blob doesn't slip through.
//
// Deliberately NOT covered yet: SRV-15 (checking the answer coming back).
// That's tracked separately; don't assume this package sees model output.
package checker

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// Decision is one of the four results SRV-07 requires. The zero value is
// Allow, and values are ordered so the strictest decision is always the
// largest — that's what makes "strictest wins" (SRV-12) a simple max().
type Decision int

const (
	Allow Decision = iota
	Mask
	KeepOnPC
	Refuse
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Mask:
		return "mask"
	case KeepOnPC:
		return "keep-on-pc"
	case Refuse:
		return "refuse"
	default:
		return "unknown"
	}
}

type FindingKind string

func (k FindingKind) String() string { return string(k) }

const (
	KindSecret     FindingKind = "secret"
	KindPII        FindingKind = "pii"
	KindClassified FindingKind = "classified"
	KindAttack     FindingKind = "attack"
)

// View records which reading of the text produced a finding (SRV-09).
type View string

const (
	ViewRaw                View = "raw"
	ViewWhitespaceStripped View = "whitespace_stripped"
	ViewInvisibleStripped  View = "invisible_stripped"
	ViewBase64Decoded      View = "base64_decoded"
)

type Finding struct {
	Kind  FindingKind
	Label string // e.g. "github_token", "email", "credit_card_number"
	View  View
	Span  string // the matched text — kept for masking; do not log verbatim upstream
}

// Policy is the per-group configuration an administrator sets (SRV-17):
// which finding kind maps to which decision, plus company-specific terms
// to treat as classified. Defaults below are sensible starting points, not
// a claim about what any real customer will want.
type Policy struct {
	Severity        map[FindingKind]Decision
	ClassifiedTerms []string
}

func DefaultPolicy() Policy {
	return Policy{
		Severity: map[FindingKind]Decision{
			KindSecret:     KeepOnPC, // SRV-13: never to an outside provider, but still usable locally
			KindPII:        Mask,     // SRV-14: masked in place, masked text sent
			KindClassified: Refuse,   // company-marked terms: nothing goes anywhere
			KindAttack:     Refuse, // G4: a prompt trying to hijack the assistant gets nothing, same as classified content

		},
		ClassifiedTerms: nil,
	}
}

type Result struct {
	Decision Decision
	// Findings is deduplicated (by kind+label+span) for readability in API
	// responses and logs. The decision itself is computed from the full,
	// non-deduplicated set across every view — see Check.
	Findings   []Finding
	MaskedText string // populated only when Decision == Mask
}

var (
	invisibleRe   = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{00AD}]`)
	base64ChunkRe = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
)

// letterSpacingRe matches a run of 4+ single word-characters each
// separated by exactly one space — "A K I A I O S..." — a common way to
// dodge a scanner looking for a contiguous token. Deliberately narrow (4+
// single-character "words" in a row): ordinary English essentially never
// does this, so it won't merge real short words together, while a spaced-
// out secret is far longer than this threshold in practice.
var letterSpacingRe = regexp.MustCompile(`\b(?:[A-Za-z0-9] ){3,}[A-Za-z0-9]\b`)

func collapseLetterSpacing(s string) string {
	return letterSpacingRe.ReplaceAllStringFunc(s, func(m string) string {
		return strings.ReplaceAll(m, " ", "")
	})
}

// Check runs the prompt through every view required by SRV-09 and returns
// the strictest applicable decision (SRV-12). If a finding shows up only in
// an altered view and not in the raw text, SRV-10 requires treating it as
// deliberately hidden — this forces at least KeepOnPC regardless of what
// that finding kind would normally map to.
func Check(text string, policy Policy) Result {
	rawFindings := scanText(text, ViewRaw, policy)

	wsStripped := stripWhitespace(text)
	wsFindings := scanText(wsStripped, ViewWhitespaceStripped, policy)

	invStripped := invisibleRe.ReplaceAllString(text, "")
	invFindings := scanText(invStripped, ViewInvisibleStripped, policy)

	b64Findings := scanBase64Segments(text, policy)

	// A separate view from the whitespace-stripped one above: that view
	// collapses ALL whitespace, which destroys the word boundaries a
	// secret-format regex needs (merging "is AKIA..." into "isAKIA...",
	// which no longer matches). This one ONLY collapses the specific
	// letter-by-letter spacing pattern, preserving normal word breaks.
	spacingCollapsed := collapseLetterSpacing(text)
	spacingFindings := scanText(spacingCollapsed, ViewWhitespaceStripped, policy)

	all := append(append(append(append(rawFindings, wsFindings...), invFindings...), b64Findings...), spacingFindings...)

	decision := Allow
	rawOnly := map[string]bool{}
	for _, f := range rawFindings {
		rawOnly[f.Kind.String()+"|"+f.Label] = true
	}

	for _, f := range all {
		sev := policy.Severity[f.Kind]
		hiddenOnly := f.View != ViewRaw && !rawOnly[f.Kind.String()+"|"+f.Label]
		if hiddenOnly && sev < KeepOnPC {
			// SRV-10: found only in an altered view -> deliberately hidden ->
			// keep on PC rather than the milder decision it would otherwise get.
			sev = KeepOnPC
		}
		if sev > decision {
			decision = sev
		}
	}

	result := Result{Decision: decision, Findings: dedupeFindings(all)}
	if len(rawFindings) > 0 {
		// Populated whenever raw findings exist, not only when Decision
		// is Mask — SanitizeForDelivery needs a masked version available
		// for KeepOnPC results too (redact-on-output beats withhold-the-
		// whole-answer for things like example credentials in code).
		result.MaskedText = maskText(text, rawFindings)
	}
	return result
}

// dedupeFindings collapses the same kind+label+span reported from multiple
// views (raw text scanned identically in the whitespace/invisible-stripped
// views when nothing was actually hidden) into one entry, so a single email
// address doesn't show up three times in an API response or audit log.
// The Check decision itself is computed BEFORE this collapse, from the full
// per-view set — deduping here only affects what gets reported, never what
// gets decided.
func dedupeFindings(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Kind.String() + "|" + f.Label + "|" + f.Span
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func scanText(text string, view View, policy Policy) []Finding {
	var findings []Finding

	for _, rule := range secretRules {
		for _, m := range rule.Regex.FindAllString(text, -1) {
			if strings.HasSuffix(m, "EXAMPLE") {
				// AWS's own documentation convention: every placeholder
				// key ID in their official docs ends in the literal word
				// "EXAMPLE" (e.g. AKIAIOSFODNN7EXAMPLE) specifically so
				// it's recognizable as non-functional. A real key ending
				// in those exact 7 characters is vanishingly unlikely.
				continue
			}
			findings = append(findings, Finding{Kind: KindSecret, Label: rule.Label, View: view, Span: m})
		}
	}

	for _, rule := range attackRules {
		for _, m := range rule.Regex.FindAllString(text, -1) {
			findings = append(findings, Finding{Kind: KindAttack, Label: rule.Label, View: view, Span: m})
		}
	}

	lower := strings.ToLower(text)
	for _, term := range policy.ClassifiedTerms {
		if term == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(term)) {
			findings = append(findings, Finding{Kind: KindClassified, Label: term, View: view, Span: term})
		}
	}
	for _, m := range classificationMarkingRe.FindAllString(text, -1) {
		findings = append(findings, Finding{Kind: KindClassified, Label: "classification_marking", View: view, Span: m})
	}

	// PII patterns and the entropy fallback are deliberately NOT scanned in
	// the whitespace/invisible-stripped views. Those views exist for SRV-09
	// evasion (a secret or classified term someone deliberately broke up to
	// dodge detection) — a real evasion concern for tokens and banned terms.
	// An email or phone number has no internal whitespace to hide in the
	// first place; running these regexes on merged text instead just
	// swallows adjacent prose into the match (the local-part character
	// class overlaps ordinary letters) and reports the same finding twice
	// under a longer, wrong span. Secrets and classified terms still get
	// full evasion coverage above; this only narrows where PII is scanned.
	if view == ViewRaw || view == ViewBase64Decoded {
		findings = append(findings, scanHighEntropy(text, view)...)
		findings = append(findings, scanPII(text, view)...)
	}

	return findings
}

func scanPII(text string, view View) []Finding {
	var findings []Finding

	for _, m := range emailRe.FindAllString(text, -1) {
		findings = append(findings, Finding{Kind: KindPII, Label: "email", View: view, Span: m})
	}
	for _, m := range phoneRe.FindAllStringIndex(text, -1) {
		start, end := m[0], m[1]
		if touchesLetter(text, start, end) {
			// A digit run glued to letters on either side (e.g. the
			// "1234567890" inside "AKIAEXAMPLE1234567890") isn't a phone
			// number — real ones appear as their own token, not embedded
			// inside a longer alphanumeric identifier.
			continue
		}
		span := text[start:end]
		digits := onlyDigits(span)
		if len(digits) >= 10 && len(digits) <= 15 && !allSameDigit(digits) {
			findings = append(findings, Finding{Kind: KindPII, Label: "phone_number", View: view, Span: span})
		}
	}
	// SRV-11: confirm before acting — a long number is only a card number if
	// it passes Luhn. This is what stops ordinary reference codes and order
	// numbers from being treated as card numbers.
	for _, m := range cardCandidateRe.FindAllString(text, -1) {
		digits := onlyDigits(m)
		if len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) {
			findings = append(findings, Finding{Kind: KindPII, Label: "credit_card_number", View: view, Span: m})
		}
	}
	for _, m := range ssnRe.FindAllString(text, -1) {
		if ssnLooksValid(m) {
			findings = append(findings, Finding{Kind: KindPII, Label: "us_ssn", View: view, Span: m})
		}
	}
	for _, m := range ibanRe.FindAllString(text, -1) {
		if ibanChecksumValid(m) {
			findings = append(findings, Finding{Kind: KindPII, Label: "iban", View: view, Span: m})
		}
	}
	for _, m := range ipv4Re.FindAllString(text, -1) {
		if !ipIsPrivate(m) {
			findings = append(findings, Finding{Kind: KindPII, Label: "ip_address", View: view, Span: m})
		}
	}
	return findings
}

// scanBase64Segments implements the "encoded parts decoded" half of SRV-09:
// it pulls out base64-looking chunks, decodes them, and scans the result.
func scanBase64Segments(text string, policy Policy) []Finding {
	var findings []Finding
	for _, chunk := range base64ChunkRe.FindAllString(text, -1) {
		decoded, err := base64.StdEncoding.DecodeString(chunk)
		if err != nil || !looksLikeText(decoded) {
			continue
		}
		findings = append(findings, scanText(string(decoded), ViewBase64Decoded, policy)...)
	}
	return findings
}

func stripWhitespace(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func looksLikeText(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 32 && c < 127 {
			printable++
		}
	}
	return printable*100/len(b) > 85
}

// touchesLetter reports whether the byte immediately before start, or
// immediately at end, is an ASCII letter. Used to reject a phone-shaped
// digit run that's actually embedded inside a longer identifier (e.g. the
// "1234567890" inside "AKIAEXAMPLE1234567890") — a real phone number
// appears as its own token, not glued to letters on either side.
func touchesLetter(text string, start, end int) bool {
	isLetter := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	if start > 0 && isLetter(text[start-1]) {
		return true
	}
	if end < len(text) && isLetter(text[end]) {
		return true
	}
	return false
}

// maskText replaces every raw-view finding span with a label placeholder.
// Only raw-view spans are masked in the outbound text — findings from
// stripped/decoded views describe evasion attempts already handled by
// forcing KeepOnPC, not text that literally appears for redaction.
func maskText(text string, rawFindings []Finding) string {
	masked := text
	for _, f := range rawFindings {
		if f.Span == "" {
			continue
		}
		placeholder := "[REDACTED:" + string(f.Kind) + "]"
		masked = strings.ReplaceAll(masked, f.Span, placeholder)
	}
	return masked
}
