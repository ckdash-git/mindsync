package checker

// SanitizeForDelivery decides what actually gets delivered once TEXT THAT
// HAS ALREADY BEEN GENERATED (a model's answer, not an incoming prompt) has
// been checked. This is deliberately a separate function from the input-
// side Check() result handling in checker.go's callers, because output has
// nowhere further to route to — an incoming prompt can be sent to a safer
// TIER (on-PC instead of public), but an answer that's about to leave the
// system either goes out as-is, goes out with the sensitive spans redacted,
// or does not go out at all.
//
// KeepOnPC and Mask are treated IDENTICALLY here (both redact rather than
// withhold), even though they mean different things on the input side.
// This matters in practice: a coding assistant's example code routinely
// contains placeholder credentials (`user:pw@host`, `AKIAEXAMPLE...`) that
// legitimately match a secret pattern without being a real secret. Fully
// withholding the whole answer over one illustrative example destroys
// otherwise-good answers for no safety benefit — redacting just that span
// preserves the rest. Refuse (classified/company-forbidden content) is the
// one decision that still withholds entirely — that line is intentionally
// held firmer.
//
// Both the server (answering via the company model) and the agent
// (answering via the on-PC model) call this identically — that's the whole
// point of it living here rather than being reimplemented per-repo, same
// reasoning as Check itself: divergence in output handling is a security
// bug, not a style difference.
func SanitizeForDelivery(result Result, original string) (deliverable string, blocked bool, reason string) {
	switch result.Decision {
	case Allow:
		return original, false, ""
	case Mask, KeepOnPC:
		return result.MaskedText, false, "the response was redacted before delivery"
	default: // Refuse — classified/forbidden content withholds entirely.
		return "", true, "the response was withheld: it matched company policy"
	}
}