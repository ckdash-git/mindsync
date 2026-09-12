# mindsync

A text-inspection library for catching secrets and personal data before
they leave your system — the same category as gitleaks or detect-secrets,
built for inline use inside an application rather than scanning a git
history.

## What it does

`checker.Check(text, policy)` runs a string through three layers and
returns one of four decisions: **allow**, **mask**, **hold** (safe to
process, but shouldn't leave this system), or **refuse**.

1. **Known-format rules** — ~20 provider-specific secret patterns (cloud
   credentials, git hosting tokens, chat/webhook URLs, payment API keys,
   JWTs, private key blocks, database connection strings with embedded
   passwords), plus checksum-**confirmed** personal data: Luhn for card
   numbers, government ID range validity, and a real mod-97 checksum for
   IBANs — not just "matches the expected shape."
2. **Entropy fallback** — catches secrets in formats nobody's written a
   pattern for yet, using Shannon entropy over contiguous alphanumeric
   runs. Deliberately scoped to raw and decoded text only; running it over
   whitespace-merged text produces false positives on ordinary prose (see
   the comment in `entropy.go`).
3. **Evasion views** — the same text re-read with whitespace stripped,
   invisible/zero-width characters stripped, and base64-decoded. Anything
   that only shows up once you strip evasion characters is treated as
   deliberately hidden and escalates the decision accordingly.

```go
import "github.com/ckdash-git/mindsync/checker"

result := checker.Check(someText, checker.DefaultPolicy())
switch result.Decision {
case checker.Allow:
    // send someText onward unchanged
case checker.Mask:
    // send result.MaskedText instead — original findings redacted in place
case checker.KeepOnPC:
    // process locally / do not forward externally
case checker.Refuse:
    // don't process at all
}
```

## Policy

`checker.Policy` maps each finding kind (`secret`, `pii`, `classified`) to
a decision, and accepts a list of caller-defined "classified" terms
checked as case-insensitive substrings. `DefaultPolicy()` gives sensible
starting values — secrets hold, personal data masks, classified terms
refuse — override per your own risk tolerance.

## Install

```bash
go get github.com/ckdash-git/mindsync
```

## Tests

```bash
go test ./...
```

22 tests: correct handling of clean text, every known-format rule, the
entropy fallback (including that it does NOT fire on ordinary prose),
checksum validation for cards/IDs/IBANs (both the valid and
looks-right-but-isn't cases), the evasion views, and finding
deduplication.

## License

Add whichever license fits your use before publishing this further —
none is currently declared.
