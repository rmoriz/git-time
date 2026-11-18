#!/bin/sh
# Probe: a trailer block can be appended to a commit object and the exact
# pre-image recovered, using commit-tree + update-ref with pinned identities.
# Proves §8.2 of the design. Expected: "PASS".
set -eu
W=$(mktemp -d "${TMPDIR:-/tmp}/gtp1.XXXXXX"); cd "$W"
git init -q .; git config user.name P; git config user.email p@e

printf 'a\n' > a; git add a
GIT_COMMITTER_DATE='2026-01-01T00:00:00+00:00' git commit -q -m subject -m body
old=$(git rev-parse HEAD)
git cat-file commit "$old" > orig.obj

# strip trailers + signature, append trailer block (the seal step)
python3 - orig.obj > msg.txt <<'PY'
import sys
raw = open(sys.argv[1], 'rb').read()
head, msg = raw.split(b"\n\n", 1)
lines = msg.split(b"\n")
while lines and (lines[-1].startswith(b"X-RFC3161") or lines[-1] == b""):
    lines.pop()
sys.stdout.buffer.write(b"\n".join(lines) + b"\n\nX-RFC3161-Imprint: sha256:00\n")
PY

a=$(git log -1 --format=%aI); an=$(git log -1 --format=%an); ae=$(git log -1 --format=%ae)
c=$(git log -1 --format=%cI); cn=$(git log -1 --format=%cn); ce=$(git log -1 --format=%ce)
tree=$(git rev-parse "$old^{tree}")
new=$(GIT_AUTHOR_NAME="$an" GIT_AUTHOR_EMAIL="$ae" GIT_AUTHOR_DATE="$a" \
      GIT_COMMITTER_NAME="$cn" GIT_COMMITTER_EMAIL="$ce" GIT_COMMITTER_DATE="$c" \
      git commit-tree "$tree" -F msg.txt)
git update-ref -m "rfc3161 seal" HEAD "$new" "$old"

# verification: rebuild the pre-image and compare byte for byte
git cat-file commit HEAD > sealed.obj
python3 - <<'PY'
raw = open('sealed.obj', 'rb').read()
head, msg = raw.split(b"\n\n", 1)
lines = msg.split(b"\n")
while lines and (lines[-1].startswith(b"X-RFC3161") or lines[-1] == b""):
    lines.pop()
rebuilt = head + b"\n\n" + b"\n".join(lines) + b"\n"
orig = open('orig.obj', 'rb').read()
assert rebuilt == orig, "pre-image differs"
print("PASS byte-identical pre-image, tree", __import__("subprocess").run(
    ["git", "rev-parse", "HEAD^{tree}"], capture_output=True, text=True).stdout.strip()[:12])
PY
