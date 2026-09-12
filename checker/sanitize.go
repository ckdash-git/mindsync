package checker

// SanitizeForDelivery decides what actually gets delivered once TEXT THAT
// HAS ALREADY BEEN GENERATED (a model's answer, not an incoming prompt) has
// been checked. This is deliberately a separate function from the input-
// side Check() result handling in checker.go's callers, because output has
// nowhere further to route to — an incoming prompt can be sent to a safer
// TIER (on-PC instead of public), but an answer that's about to leave the
// system either goes out as-is, goes out with the sensitive spans redacted,
// or does not go out at all. There is no "keep this answer on the PC"
// destination once it's already been generated and is on its way back to
// whoever asked.
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
	case Mask:
		return result.MaskedText, false, "the response was redacted before delivery"
	default: // KeepOnPC or Refuse — neither has anywhere further to go once
		// generated, so both mean "withhold" on the output side.
		return "", true, "the response was withheld: it matched company policy"
	}
}