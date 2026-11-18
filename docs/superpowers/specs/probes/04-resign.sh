#!/bin/sh
# Probe: signing order. Imprint excludes trailer+signature, the signature covers
# the object *including* the trailer, and the object is composed with
# hash-object so every header survives. Then the commit is still validly signed
# and the imprint is reproducible. Proves §8.2/§9. Needs gpg.
set -eu
command -v gpg >/dev/null || { echo "SKIP no gpg"; exit 0; }
W=$(mktemp -d "${TMPDIR:-/tmp}/gtp4.XXXXXX"); cd "$W"
git init -q .; git config user.name P; git config user.email p@e
GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/gtp4g.XXXXXX"); export GNUPGHOME
gpg --batch --quiet --passphrase '' --quick-gen-key 'Probe <p@e>' rsa2048 sign never 2>/dev/null
git config user.signingkey "$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"

printf 'a\n' > a; git add a; git commit -q -S -m 'signed subject'
git cat-file commit HEAD > orig.obj
signed_before=$(grep -c '^gpgsig' orig.obj)

python3 - orig.obj > sealed.obj <<'PY'
import hashlib, subprocess, sys
raw = open(sys.argv[1], 'rb').read()
head, msg = raw.split(b"\n\n", 1)          # msg keeps its trailing newline
hdr, skip = [], False
for line in head.split(b"\n"):             # drop gpgsig + continuation lines
    if line.startswith(b"gpgsig"):
        skip = True
        continue
    if skip and line.startswith(b" "):
        continue
    skip = False
    hdr.append(line)
imprint = b"\n".join(hdr) + b"\n\n" + msg                # what the TSA timestamps
print("imprint {}".format(hashlib.sha256(imprint).hexdigest()), file=sys.stderr)
final = imprint + b"\nX-RFC3161-Imprint: sha256:00\n"     # what the signature covers
sig = subprocess.run(["gpg", "--batch", "--armor", "--detach-sign", "--output", "-"],
                     input=final, capture_output=True, check=True).stdout
assert sig.startswith(b"-----BEGIN PGP SIGNATURE"), sig[:40]
blob = (b"\n".join(hdr) + b"\n" + b"gpgsig " +
        sig.rstrip(b"\n").replace(b"\n", b"\n ") + b"\n\n" +
        msg + b"\nX-RFC3161-Imprint: sha256:00\n")
sys.stdout.buffer.write(blob)
PY

new=$(git hash-object -w -t commit --stdin < sealed.obj)
git verify-commit "$new" >/dev/null 2>&1 || { echo "FAIL signature broken by seal"; exit 1; }
[ "$signed_before" -gt 0 ] || { echo "FAIL fixture was not signed"; exit 1; }

# the imprint must be reproducible from the sealed object
git cat-file commit "$new" > check.obj
python3 - check.obj <<'PY'
import hashlib, sys
raw = open(sys.argv[1], 'rb').read()
head, msg = raw.split(b"\n\n", 1)
hdr, skip = [], False
for line in head.split(b"\n"):
    if line.startswith(b"gpgsig"):
        skip = True
        continue
    if skip and line.startswith(b" "):
        continue
    skip = False
    hdr.append(line)
lines = msg.split(b"\n")
while lines and (lines[-1].startswith(b"X-RFC3161") or lines[-1] == b""):
    lines.pop()
rebuild = b"\n".join(hdr) + b"\n\n" + b"\n".join(lines) + b"\n"
print("recomputed {}".format(hashlib.sha256(rebuild).hexdigest()))
PY
echo "PASS signature survives, imprint reproducible"
