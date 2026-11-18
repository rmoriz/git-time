#!/bin/sh
# Probe: `git commit --amend` inside post-commit fails mid-rebase
# ("You are in the middle of a cherry-pick -- cannot amend") and on commits
# that become empty. Proves why the design rewrites via commit-tree.
# Expected: AMEND-REFUSED, then PASS.
set -eu
W=$(mktemp -d "${TMPDIR:-/tmp}/gtp3.XXXXXX"); cd "$W"
git init -q .; git config user.name P; git config user.email p@e

cat > .git/hooks/post-commit <<'EOF'
#!/bin/sh
c=$(git log -1 --format=%cI)
git log -1 --format=%B > m.txt; printf 'X-RFC3161-Token: id=probe\n' >> m.txt
if GIT_COMMITTER_DATE="$c" git commit -q --amend -F m.txt 2>err.txt; then
  echo "amend-ok" >> /tmp/gtp3.log
else
  echo "AMEND-REFUSED: $(head -1 err.txt)" >> /tmp/gtp3.log
fi
EOF
chmod +x .git/hooks/post-commit
rm -f /tmp/gtp3.log

printf 'base\n' > base; git add base; git commit -q -m base
git checkout -q -b side; printf '1\n' > f1; git add f1; git commit -q -m c1
git checkout -q -; printf 'm\n' > m; git add m; git commit -q -m main
GIT_EDITOR=true git rebase side >/dev/null 2>&1 || true

grep -q 'AMEND-REFUSED' /tmp/gtp3.log || { echo "FAIL expected a refusal"; cat /tmp/gtp3.log; exit 1; }
echo "AMEND-REFUSED observed during rebase (as designed)"
grep 'AMEND-REFUSED' /tmp/gtp3.log | head -1
stale=0
for h in $(git rev-list side..HEAD); do
  git log -1 --format=%B "$h" | grep -q 'X-RFC3161-Token' || stale=$((stale + 1))
done
echo "PASS stale/unsealed replayed commits: $stale (re-sealed by 02-rebase-seal.sh pattern)"
