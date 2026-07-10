#!/usr/bin/env bash
# Install repo git hooks. Idempotent: safe to re-run. Points core.hooksPath at
# scripts/ so the tracked pre-push-guard runs on every push without copying into
# the untracked .git/hooks dir.
#
# Run once after clone:  bash scripts/install-hooks.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# git looks for a hook named exactly "pre-push" in core.hooksPath. Provide a
# thin dispatcher so the descriptive filename (pre-push-guard.sh) stays readable.
mkdir -p .githooks
cat > .githooks/pre-push <<'EOF'
#!/usr/bin/env bash
exec "$(git rev-parse --show-toplevel)/scripts/pre-push-guard.sh" "$@"
EOF
chmod +x .githooks/pre-push scripts/pre-push-guard.sh

git config core.hooksPath .githooks
echo "Installed: core.hooksPath -> .githooks (pre-push-guard active)."
echo "Bypass a single push with: git push --no-verify"
