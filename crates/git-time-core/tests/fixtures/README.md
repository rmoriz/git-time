# RFC 3161 fixtures

Captured 2026-11-18 from https://freetsa.org/tsr (FreeTSA, no signup).

| File | What it is |
|---|---|
| `query_sha256_cert.tsq` | DER `TimeStampReq` produced by `openssl ts -query -data payload.bin -sha256 -cert` |
| `resp_granted_freetsa.tsr` | DER `TimeStampResp` with `status=granted(0)` and an embedded token (4644 bytes) |
| `resp_rejected_freetsa.tsr` | DER `TimeStampResp` with `status=rejected(2)`, failure info `unacceptedPolicy`, no token (50 bytes) |
| `payload.bin` | the exact bytes whose SHA-256 is the message imprint in the two responses above |

`payload.bin` is `git-time fixture payload\n` (25 bytes). Regenerate the query with:

```sh
openssl ts -query -data payload.bin -sha256 -cert -out query_sha256_cert.tsq
```

The rejection was produced by requesting policy `1.3.6.1.4.1.99999.1`, which FreeTSA
does not serve, so it returns `status=rejected` with `unacceptedPolicy` and no token.

These fixtures are test data only. They must never be accepted as evidence by `verify`
without a pinned FreeTSA anchor — that is exactly the fail-closed behaviour Task 9 pins.
