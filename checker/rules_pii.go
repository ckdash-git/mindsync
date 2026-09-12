package checker

import (
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var (
	emailRe         = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phoneRe         = regexp.MustCompile(`\+?\d[\d\-\s]{8,14}\d`)
	cardCandidateRe = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	// US SSN format only. Format-valid does not mean real — see
	// ssnLooksValid for the area-number check that catches obviously fake
	// ones (000/666/900-999), same spirit as the card Luhn check: confirm
	// before acting (SRV-11).
	ssnRe = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// IBAN: 2 letters, 2 check digits, up to 30 alphanumerics. Format alone
	// is cheap to fake by accident (any long alphanumeric code can look
	// like this) — ibanChecksumValid below does the real confirmation.
	ibanRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`)
)

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// allSameDigit rejects filler like "0000000000" or "1111111111" — no real
// phone number is a single repeated digit, and format-only regexes like
// phoneRe have no checksum to fall back on the way cards/IBANs do, so this
// is the cheapest confirmation available (SRV-11's spirit: don't act on an
// unconfirmed match).
func allSameDigit(digits string) bool {
	if digits == "" {
		return false
	}
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			return false
		}
	}
	return true
}

func luhnValid(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n, err := strconv.Atoi(string(digits[i]))
		if err != nil {
			return false
		}
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// ssnLooksValid rejects the area-number ranges the SSA has never issued
// (000, 666, 900-999) — enough to catch placeholder/fake SSNs in test data
// and docs without needing the full SSA allocation table.
func ssnLooksValid(ssn string) bool {
	digits := onlyDigits(ssn)
	if len(digits) != 9 {
		return false
	}
	area, err := strconv.Atoi(digits[0:3])
	if err != nil {
		return false
	}
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	group := digits[3:5]
	serial := digits[5:9]
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// ibanChecksumValid implements the standard IBAN mod-97 check (ISO 7064
// MOD 97-10): move the first 4 characters to the end, convert letters to
// numbers (A=10 ... Z=35), and the result must be congruent to 1 mod 97.
// This is what turns "looks like an IBAN" into "confirmed", the same
// confirm-before-acting principle as the card Luhn check (SRV-11).
func ibanChecksumValid(iban string) bool {
	iban = strings.ToUpper(strings.ReplaceAll(iban, " ", ""))
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	rearranged := iban[4:] + iban[0:4]

	var numeric strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			numeric.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			numeric.WriteString(strconv.Itoa(int(r-'A') + 10))
		default:
			return false
		}
	}

	n := new(big.Int)
	if _, ok := n.SetString(numeric.String(), 10); !ok {
		return false
	}
	mod := new(big.Int).Mod(n, big.NewInt(97))
	return mod.Int64() == 1
}
