# dvsanitizer256

This fork replaces upstream's truncated AES-derived record IDs
with full HMAC-SHA-256 pseudonyms. It is not an upstream release or a complete
implementation of the accompanying secure-publication proposal.

## Identifier contract

Each run requires a fresh, cryptographically random 32-byte key for the election
and an explicit `--election-id` including jurisdiction. Matching CSV CVRs, JSON
CVRs and TIF/SHA filenames use the same transformation. Reuse both key and exact
context for all related releases; never reuse keys for different elections.

The HMAC input is the ASCII domain `DVSanitizer-HMAC-SHA256-v1` followed by a
zero byte, an eight-byte unsigned big-endian UTF-8 context byte length, the context
bytes, then tabulator, batch and original record ID as three four-byte unsigned
big-endian integers. Output is `0x` plus all 64 lowercase hexadecimal digest
digits. Parsing numeric IDs first makes leading zeros consistent across formats.
Image side/page suffixes remain intact. This format breaks compatibility with
previous AES outputs: regenerate all related publication copies together.

## Build and run

Requires Go 1.19 or later. No third-party Go dependencies are needed.

```sh
go test ./...
go build -o dvsanitizer .
mkdir clean-cvr clean-images
# Keep this key path outside every publication/output directory.
./dvsanitizer --gen-seed --key-file /private/secure/election.key \
  --election-id 'GA|Example County|2026-11-03' \
  --sanitize-csv --input originals/CVR.csv --output-dir clean-cvr
./dvsanitizer --key-file /private/secure/election.key \
  --election-id 'GA|Example County|2026-11-03' \
  --sanitize-tif-dir --input originals/images --output-dir clean-images
```

Create the private key's parent directory first. Generated keys are saved using
exclusive creation and mode 0600; existing key files are never overwritten.
Keys are no longer printed. Protect the directory and backups; never include a
key or crosswalk in a public package. Restrict and document custody and follow an
approved retention/destruction policy. A failed run may leave a newly generated
key file: reuse it for a retry rather than generating over it. Existing key files
must be regular files with no group/other permissions (POSIX permission check).
`--seed` accepts a 64-digit hex key only for compatibility, but exposes the key in
command arguments and should be avoided. Format validation cannot prove entropy:
use the generator, not a password. Old 16-byte seeds are not supported.

JSON ZIP mode uses `--sanitize-json-zip`. Existing input and output protections
and the unfinished-output staging behavior remain in place. Never run third-party
sanitization software on election management systems. Preserve original records
and chain of custody; use copies on a separate secured system.

## Publication limitations

This change covers keyed identifiers and key handling only. Upstream CSV/JSON
record reordering and image processing order remain based on sanitized IDs; this
is not independent random shuffling. Upstream preserves tabulator/batch fields,
directory structure, embedded image data, and most other metadata. Split JSON
files retain their original group membership. This version does not implement
comprehensive timestamp/metadata scrubbing, global reshuffling, image barcode
redaction, full dataset collision/matching/tally validation, or independent voter
linkage testing. Do not treat its output as approved for public release.

Before publication, implement those remaining controls, validate every CVR/image
association and vote total, rebuild and inspect archives, and independently test
sequence reconstruction and linkage using auxiliary data and prior releases.
Stop on mismatches or privacy failures. HMAC does not cure the scanner flaw,
protect the originals, or undo information disclosed in earlier releases.

## Provenance and license

Based on https://github.com/AuburnCyber/dvsanitizer (see git history for the base).
Upstream uses a different AES-derived deterministic transformation, not HMAC.
Original GPL-3.0 license and disclaimers apply; see LICENSE.
