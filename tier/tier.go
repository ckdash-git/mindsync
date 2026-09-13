// Package tier implements "which model answers" — one of the two
// independent choices SRV-47 requires (the other, "where work runs", is a
// routing decision each repo handles itself). This package exists so the
// server and the PC agent apply IDENTICAL escalation and override rules —
// divergence here would mean, e.g., the agent letting a sensitive prompt
// reach a public provider under conditions the server would have refused,
// which is exactly the kind of security-relevant drift this project
// extracts shared logic specifically to prevent.
package tier

import "cigit01.ninjaconnect.co.in/ckdash/mindsync/checker"

// Tier is one of the three places an answer can come from (§6.1).
type Tier string

const (
	OnPC    Tier = "on-pc"   // the model on the PC that ran the task
	Private Tier = "private" // the company's own model
	Public  Tier = "public"  // an external provider
)

// order is the FIXED escalation sequence from §9.2a: "On the PC -> the
// company's own model -> a public provider." When a chosen tier can't
// answer, the next tier in THIS order is tried — never a different order,
// regardless of which tier was originally chosen.
var order = []Tier{OnPC, Private, Public}

// MustStayInCompany reports whether a checked prompt's decision means it
// may never reach a public provider — PC-46's floor. KeepOnPC is the
// checker's "never send this externally" severity (secrets); that maps
// directly onto "must stay inside the company" here. Refuse (classified
// content) is a separate, stricter axis handled by the caller before
// tier resolution even starts — Resolve assumes Refuse has already been
// handled and won't be called for it.
func MustStayInCompany(d checker.Decision) bool {
	return d == checker.KeepOnPC
}

// Resolve applies SRV-49 (the check may only move the user's choice
// toward something SAFER, never riskier) and returns the ordered list of
// tiers to actually attempt.
//
// If the content must stay inside the company and the user chose Public,
// the choice is overridden to Private before anything is tried — SRV-50
// requires the caller to tell the user this happened and why, which is
// exactly what overridden/reason are for.
//
// The returned tier list starts at the (possibly-overridden) choice and
// continues through the fixed order — capped BEFORE Public if the content
// must stay inside the company (PC-46: never reaches public, refused
// instead if nothing safe in the list can answer).
func Resolve(chosen Tier, decision checker.Decision) (tiersToTry []Tier, overridden bool, reason string) {
	if chosen == "" {
		chosen = OnPC
	}

	effective := chosen
	mustStay := MustStayInCompany(decision)
	if mustStay && chosen == Public {
		effective = Private
		overridden = true
		reason = "moved to the company's private model — this prompt must stay inside the company"
	}

	startIdx := indexOf(order, effective)
	if startIdx == -1 {
		startIdx = 0
	}

	capIdx := len(order)
	if mustStay {
		capIdx = indexOf(order, Private) + 1 // excludes Public
	}

	for i := startIdx; i < capIdx; i++ {
		tiersToTry = append(tiersToTry, order[i])
	}
	return tiersToTry, overridden, reason
}

func indexOf(s []Tier, v Tier) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}