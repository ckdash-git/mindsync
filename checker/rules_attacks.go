package checker

import "regexp"

// attackRule is one prompt-injection pattern. Unlike secretRules (provider-
// specific formats with essentially no ambiguity), these are necessarily
// heuristic — natural language has no fixed format for "try to hijack the
// assistant" the way an AWS key has a fixed format. Each rule here is
// deliberately narrow and anchored on a specific verb+object or a named,
// real jailbreak technique, rather than a broad keyword match, precisely
// so ordinary sentences that merely mention "instructions" or "rules"
// don't get caught — see the attacks.json corpus's own "allow" cases,
// which exist specifically to catch overreach here.
type attackRule struct {
	Label string
	Regex *regexp.Regexp
}

var attackRules = []attackRule{
	// "Ignore/disregard/forget" + "instructions/system prompt/rules" within
	// the same clause (no period in between, so it doesn't drift into an
	// unrelated following sentence). Deliberately does NOT fire on
	// "disregard" alone — attacks.json's own allow case ("disregard my
	// earlier question about the budget") shows the verb alone is
	// meaningless; it's the OBJECT (instructions/rules/system prompt) that
	// makes it an override attempt.
	{"instruction-override", regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\b[^.]{0,40}\b(instructions?|system prompt|rules)\b`)},
	// A companion to the rule above, specifically for text that survived
	// letter-spacing collapse (see collapseLetterSpacing in checker.go):
	// collapsing "i g n o r e a l l ... i n s t r u c t i o n s" glues the
	// WHOLE phrase into one word ("ignoreallpreviousinstructions"), which
	// destroys the \b boundaries the rule above needs around "ignore"
	// itself. This variant has no boundary requirement and no spaces in
	// its gap — which is exactly what makes it safe to run unconditionally:
	// ordinary English always has real spaces between these words, so this
	// can only ever match text that's already been glued together, never
	// a normal sentence.
	{"instruction-override-glued", regexp.MustCompile(`(?i)(ignore|disregard|forget)[a-z]{0,60}(instructions?|systemprompt|rules)`)},

	// Same concept in Japanese: 指示 (instructions) and 無視 (ignore)
	// co-occurring within a short span. Kept as simple co-occurrence
	// (not a fixed phrase) since word order varies more freely than
	// English's fixed verb-object pattern.
	{"instruction-override-ja", regexp.MustCompile(`指示.{0,20}無視|無視.{0,20}指示`)},

	// A verb asking the assistant to surface its own system prompt.
	{"system-prompt-probe", regexp.MustCompile(`(?i)\b(repeat|reveal|show|print|tell me|what is)\b.{0,30}\bsystem prompt\b`)},
	// システムプロンプト (katakana loanword for "system prompt") is specific
	// enough on its own — this phrase essentially never appears in
	// ordinary Japanese conversation for any other reason.
	{"system-prompt-probe-ja", regexp.MustCompile(`システムプロンプト`)},

	// Named, real jailbreak techniques — safe to match on presence alone,
	// since nobody says "DAN mode" or "god mode" for any innocent reason.
	{"role-hijack", regexp.MustCompile(`(?i)\b(DAN mode|god mode|jailbreak(ed)? mode)\b`)},
	// "Developer mode" specifically needs corroboration before flagging —
	// unlike DAN/god mode, this phrase could plausibly name a real
	// product feature someone is innocently asking about.
	{"role-hijack-developer-mode", regexp.MustCompile(`(?i)\bdeveloper mode\b.{0,60}\b(no rules|without (any )?restrictions|unrestricted|answer freely)\b`)},

	// Asking the assistant to send conversation content to an external
	// destination. Requiring a URL is the key discriminator: it's what
	// separates this from an ordinary "send the summary to the team"
	// request, which never names an external address.
	{"exfiltration-request", regexp.MustCompile(`(?i)\bsend\b.{0,30}\b(this conversation|our conversation|this chat|the above)\b.{0,30}https?://`)},

	// A "System:" line embedded mid-message, claiming elevated access —
	// text pretending to be a role it isn't. (?m) so ^ matches after an
	// embedded newline, since this typically appears partway through a
	// longer pasted block, not as the message's own first line.
	{"false-authority", regexp.MustCompile(`(?im)^\s*system\s*:.*\b(granted|full access|authorized|admin access|override)\b`)},
	// A bracketed role tag ([admin]:, [system]:, [root]:) is a strong,
	// low-false-positive signal on its own — this specific bracket-colon
	// shape essentially never appears in ordinary prose.
	{"false-authority-bracket", regexp.MustCompile(`(?i)\[(admin|system|root|developer)\]\s*:`)},
}