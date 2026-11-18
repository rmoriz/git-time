#!/bin/sh
# Probe: commit-tree + update-ref seals commits *during* rebase, where
# `git commit --amend` is refused. Proves §6/§8.2. Expected: "PASS".
set -eu
W=$(mktemp -d "${TMPDIR:-/tmp}/gtp2.XXXXXX"); cd "$W"
git init -q .; git config user.name P; git config user.email p@e

cat > seal.sh <<'EOF'
#!/bin/sh
set -e
git cat-file commit HEAD > raw.obj
python3 - raw.obj > msg.txt <<'PY'
import sys
raw = open(sys.argv[1], 'rb').read()
head, msg = raw.split(b"\n\n", 1)
lines = msg.split(b"\n")
while lines and (lines[-1].startswith(b"X-RFC3161") or lines[-1] == b""):
    lines.pop()
sys.stdout.buffer.write(b"\n".join(lines) + b"\n\nX-RFC3161-Token: id=probe; tst=AA\n")
PY
a=$(git log -1 --format=%aI); an=$(git log -1 --format=%an); ae=$(git log -1 --format=%ae)
c=$(git log -1 --format=%cI); cn=$(git log -1 --format=%cn); ce=$(git log -1 --format=%ce)
tree=$(git rev-parse HEAD^{tree}); ps=""
for p in $(git rev-parse HEAD^@); do ps="$ps -p $p"; done
new=$(GIT_AUTHOR_NAME="$an" GIT_AUTHOR_EMAIL="$ae" GIT_AUTHOR_DATE="$a" \
      GIT_COMMITTER_NAME="$cn" GIT_COMMITTER_EMAIL="$ce" GIT_COMMITTER_DATE="$c" \
      git commit-tree $ps "$tree" -F msg.txt)
git update-ref -m "rfc3161 seal" HEAD "$new" "$(git rev-parse HEAD)"
EOF
chmod +x seal.sh
printf '#!/bin/sh\n"$PWD/seal.sh"\n' > .git/hooks/post-commit; chmod +x .git/hooks/post-commit

printf 'base\n' > base; git add base; git commit -q -m base
git checkout -q -b side
printf '1\n' > f1; git add f1; git commit -q -m c1
printf '2\n' > f2; git add f2; git commit -q -m c2
git checkout -q -
printf 'm\n' > m; git add m; git commit -q -m main

GIT_EDITOR=true git rebase side >/dev/null 2>&1
echo "rebase exit: $?"
unsealed=0
for h in $(git rev-list side..HEAD); do
  git log -1 --format=%B "$h" | grep -q 'X-RFC3161-Token' || unsealed=$((unsealed + 1))
done
if [ "$unsealed" -ne 0 ]; then echo "FAIL $unsealed replayed commit(s) unsealed"; exit 1; fi
echo "PASS every replayed commit sealed"
git log --format='%h %s' | cat
