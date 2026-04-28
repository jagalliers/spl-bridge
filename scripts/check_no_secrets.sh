#!/usr/bin/env bash
# Defense-in-depth secret scanner. Runs both as a pre-commit hook (on
# the staged set) and in CI (on the full tracked tree).
#
# Exit code:
#   0 - no candidate secret patterns found
#   1 - one or more matches; commit is blocked
#
# What it looks for:
#   * Known lab credential strings that surfaced during this project
#   * Vendor-specific key prefixes (AWS, GitHub, Stripe, Google API)
#   * Private-key PEM block headers
#   * JWT-shaped tokens (header.body.signature)
#
# False positives:
#   * If a string is unavoidable (test fixture, doc snippet), tag the
#     line with the literal string `secret-scan-allow` to skip it.

set -uo pipefail

# Pick the file set: pre-commit passes staged paths as args; CI calls
# this with no args -> we scan all tracked files. We avoid `mapfile`
# because macOS still ships bash 3.2 in /bin/bash where mapfile is
# absent.
if [[ $# -gt 0 ]]; then
    files=("$@")
else
    files=()
    while IFS= read -r line; do
        files+=("$line")
    done < <(git ls-files)
fi

if [[ ${#files[@]} -eq 0 ]]; then
    exit 0
fi

# Patterns. Anchor where useful to keep the false-positive rate sane.
patterns=(
    'Letmeinnow'
    'AKIA[0-9A-Z]{16}'
    'ASIA[0-9A-Z]{16}'
    'AGPA[0-9A-Z]{16}'
    'sk_live_[0-9a-zA-Z]{16,}'
    'rk_live_[0-9a-zA-Z]{16,}'
    'ghp_[A-Za-z0-9]{36,}'
    'gho_[A-Za-z0-9]{36,}'
    'ghs_[A-Za-z0-9]{36,}'
    'AIza[0-9A-Za-z_\-]{35}'
    '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
    'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
)

# Build a single ERE alternation - one grep invocation, fast.
joined=""
for p in "${patterns[@]}"; do
    if [[ -z "$joined" ]]; then
        joined="$p"
    else
        joined="$joined|$p"
    fi
done

# Skip files we cannot scan or never want to scan.
skip_re='\.(png|jpg|jpeg|gif|webp|pdf|ico|woff2?|ttf|eot|mp4|mov|zip|tar\.gz|tgz)$'

violations=0
for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    if [[ "$f" =~ $skip_re ]]; then
        continue
    fi
    # The script itself contains the patterns by definition; allow it.
    if [[ "$f" == "scripts/check_no_secrets.sh" ]]; then
        continue
    fi
    while IFS= read -r line; do
        # Skip lines explicitly allow-listed.
        if [[ "$line" == *"secret-scan-allow"* ]]; then
            continue
        fi
        printf 'SECRET-CANDIDATE: %s: %s\n' "$f" "$line" >&2
        violations=$((violations + 1))
    done < <(grep -EnH -- "$joined" "$f" 2>/dev/null || true)
done

if [[ $violations -gt 0 ]]; then
    printf 'check_no_secrets: %d candidate secret pattern(s) found.\n' "$violations" >&2
    printf 'If a match is intentional (test fixture, doc), append "# secret-scan-allow" on the line.\n' >&2
    exit 1
fi

exit 0
