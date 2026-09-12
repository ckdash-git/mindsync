package checker

import "regexp"

// secretRule is one known-format credential pattern. The label set here is
// adapted from gitleaks' (github.com/gitleaks/gitleaks) maintained ruleset —
// same idea (a table of provider-specific formats beats hand-rolling a
// handful of regexes), ported to Go regexp syntax rather than imported as a
// dependency, since we only need the patterns, not the git-scanning tool
// built around them.
type secretRule struct {
	Label string
	Regex *regexp.Regexp
}

var secretRules = []secretRule{
	{"aws_access_key_id", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"aws_secret_access_key", regexp.MustCompile(`(?i)aws_secret_access_key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`)},
	{"gcp_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`)},
	{"github_fine_grained_pat", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{"gitlab_pat", regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+`)},
	{"stripe_secret_key", regexp.MustCompile(`\bsk_(live|test)_[0-9A-Za-z]{24,}\b`)},
	{"stripe_restricted_key", regexp.MustCompile(`\brk_(live|test)_[0-9A-Za-z]{24,}\b`)},
	{"twilio_api_key", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	{"sendgrid_api_key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`)},
	{"npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"discord_webhook", regexp.MustCompile(`https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+`)},
	{"square_access_token", regexp.MustCompile(`\bsq0atp-[0-9A-Za-z\-_]{22}\b`)},
	{"mailgun_api_key", regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_\-]{5,}\b`)},
	{"private_key_block", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"db_connection_string_with_password", regexp.MustCompile(`(?i)\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+`)},
	{"generic_api_key_assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}`)},
}
