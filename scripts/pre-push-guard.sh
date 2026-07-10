#!/usr/bin/env bash
# Pre-push guard: aborts a push if any tracked, about-to-be-pushed blob contains
# a disallowed term. Fail-closed: a match on any pushed commit tip blocks the push.
#
# The denylist is stored base64-encoded (PATTERN_B64) so this tracked file does
# NOT itself contain any of the literal disallowed strings — the guard cannot be
# its own false positive, and no disallowed literal is published via this script.
#
# Install: run scripts/install-hooks.sh (sets core.hooksPath=.githooks).
# Bypass a single push (deliberate, logged by git): git push --no-verify
set -euo pipefail

# base64(extended-regex denylist). Decode at runtime; never inline the literals.
PATTERN_B64='Y2xhdWRlfGFudGhyb3BpY3xcYm9wdXNcYnxcYnNvbm5ldFxifFxbMW1cXXxcYkxMTVxifFxiR1BUXGJ8Y29waWxvdHwoXnxbXls6YWxudW06XV0pQUkoW15bOmFsbnVtOl1dfCQpfFswLTldKy1hZ2VudHxzdWJhZ2VudHxhZ2VudCB3b3JrZmxvd3zOlFN85LiA5pyf5LiA5LyafFxiY3JlZG9cYnx0aGVybW9keW5hbWljfGVwaXN0ZW1pY3x3b2xmIGRvY3RyaW5lfHRlZXRoIHJldGFpbmVkfGVhZ2VyLm9yaWdhbWl8XGJMT09NXGJ8Q0xBVURFXC5tZHxhbWF6b258XGJkYW5pZWxcYnxib3JvbmRpYXxkYWJvcm9uZHxyZW4gYXNoZXJ8ZnJlZS1yZW58U2xvcHRyb3B5fGljcy1zY29wZXwvVXNlcnMv'
BANNED=$(printf '%s' "$PATTERN_B64" | base64 --decode)

# The ban is doc-scoped: markdown, config, text — not compiled source (source
# comments may retain internal shorthand). This script and the hook are excluded
# so the encoded denylist never trips itself.
SRC_EXCLUDES=(':(exclude)*.rs' ':(exclude)*.toml' ':(exclude).gitignore' ':(exclude)scripts/pre-push-guard.sh' ':(exclude)scripts/install-hooks.sh' ':(exclude).githooks/pre-push')

status=0
zero="0000000000000000000000000000000000000000"

scan_tree() {
  local sha="$1" hits
  hits=$(git grep -inE "$BANNED" "$sha" -- . "${SRC_EXCLUDES[@]}" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "BLOCKED: disallowed term(s) found in tree at ${sha:0:8}:" >&2
    echo "$hits" | head -40 >&2
    status=1
  fi
}

# git passes "<local ref> <local sha> <remote ref> <remote sha>" per line on stdin.
while read -r local_ref local_sha remote_ref remote_sha; do
  [ "$local_sha" = "$zero" ] && continue   # branch deletion, nothing to scan
  scan_tree "$local_sha"
done

if [ "$status" -ne 0 ]; then
  echo "" >&2
  echo "Push aborted by pre-push-guard. Remove the flagged content, or override with --no-verify if intentional." >&2
  exit 1
fi
exit 0
