#!/bin/sh
# Probe: the rebuild primitive matters. `commit-tree` silently drops the
# `mergetag` header of a merge of a signed tag; `hash-object -w -t commit`
# preserves every header byte (mergetag, encoding, unknown headers, order).
# Proves §6/§8.2. Expected: "PASS" plus a DROPPED/kept pair.
set -eu
command -v gpg >/dev/null || { echo "SKIP no gpg"; exit 0; }
W=$(mktemp -d "${TMPDIR:-/tmp}/gtp6.XXXXXX"); cd "$W"
git init -q .; git config user.name P; git config user.email p@e
GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/gtp6g.XXXXXX"); export GNUPGHOME
gpg --batch --quiet --passphrase '' --quick-gen-key 'Probe <p@e>' rsa2048 sign never 2>/dev/null
git config user.signingkey "$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"

printf 'a\n' > a; git add a; git commit -q -m base
git checkout -q -b side; printf 'b\n' > b; git add b; git commit -q -m side
git tag -s -m 'tag msg' v1
git checkout -q -; printf 'c\n' > c; git add c; git commit -q -m main
git merge -q --no-ff v1 -m 'merge tag'

git cat-file commit HEAD > orig.obj
grep -q '^mergetag' orig.obj || { echo "SKIP merge carried no mergetag"; exit 0; }

tree=$(git rev-parse HEAD^{tree}); p1=$(git rev-parse HEAD^1); p2=$(git rev-parse HEAD^2)
git show -s --format=%B HEAD > msg.txt
if GIT_COMMITTER_DATE="$(git log -1 --format=%cI)" git commit-tree -p "$p1" -p "$p2" "$tree" -F msg.txt > ct.oid 2>/dev/null; then
  if git cat-file commit "$(cat ct.oid)" | grep -q '^mergetag'; then
    echo "UNEXPECTED commit-tree kept mergetag"
  else
    echo "DROPPED commit-tree loses mergetag"
  fi
fi

python3 - orig.obj > rebuilt.obj <<'PY'
import sys
raw = open(sys.argv[1], 'rb').read()
head, msg = raw.split(b"\n\n", 1)
sys.stdout.buffer.write(head + b"\n\n" + msg + b"\nX-RFC3161-Token: id=x\n")
PY
new=$(git hash-object -w -t commit --stdin < rebuilt.obj)
git cat-file commit "$new" > kept.obj
for h in mergetag encoding x-unknown; do
  git cat-file commit "$new" | grep -qi "^$h" && echo "kept $h"
done
python3 - <<'PY'
orig = open("orig.obj", "rb").read()
kept = open("kept.obj", "rb").read()
assert kept.startswith(orig.rstrip(b"\n")), "headers or message changed"
print("PASS hash-object preserves headers and message byte-exactly")
PY
