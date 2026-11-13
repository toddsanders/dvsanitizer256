package sanitize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"
)

const ONE_MILLION = 1000000

const publicIDBytes = 16

type ballotIdentity [3]uint32

var seenPublicIDs map[string]ballotIdentity

var recordKey []byte
var recordContext string

// Initialize is retained for package callers. Production releases should use
// InitializeForElection with an explicit, stable election/jurisdiction scope.
func Initialize(key []byte) { InitializeForElection(key, "") }

// InitializeForElection copies a raw 256-bit key. Context must be identical for
// all related CVR and image runs, and different elections must use fresh keys.
func InitializeForElection(key []byte, context string) {
	if len(key) != 32 {
		panic("sanitizer requires a raw 256-bit key")
	}
	recordKey = append([]byte(nil), key...)
	recordContext = context
	seenPublicIDs = make(map[string]ballotIdentity)
}

func createCleanRecordID(tabID, batchID, dirtyRecordID uint32) string {
	if len(recordKey) != 32 {
		panic("sanitizer not initialized")
	}
	mac := hmac.New(sha256.New, recordKey)
	// Versioned domain, byte length + UTF-8 context, then three fixed-width
	// unsigned big-endian IDs: unambiguous across formats and leading zeros.
	mac.Write([]byte("DVSanitizer-HMAC-SHA256-v1\x00"))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(recordContext)))
	mac.Write(length[:])
	mac.Write([]byte(recordContext))
	var ids [12]byte
	binary.BigEndian.PutUint32(ids[0:4], tabID)
	binary.BigEndian.PutUint32(ids[4:8], batchID)
	binary.BigEndian.PutUint32(ids[8:12], dirtyRecordID)
	mac.Write(ids[:])
	digest := mac.Sum(nil)
	id := "0x" + hex.EncodeToString(digest[:publicIDBytes])
	if err := registerPublicID(id, ballotIdentity{tabID, batchID, dirtyRecordID}); err != nil {
		// Do not expose original IDs, keys or a crosswalk in error output. Fatal
		// termination leaves outputs in the unfinished staging directory.
		log.Fatal(err)
	}
	return id
}

// The registry spans a complete processing run. Repeated references to a ballot
// (CVR, image sides and SHA companions) are valid; distinct inputs must not alias.
func registerPublicID(id string, ballot ballotIdentity) error {
	if previous, ok := seenPublicIDs[id]; ok && previous != ballot {
		return errors.New("shortened HMAC identifier collision; stop release and regenerate all related datasets with a fresh key")
	}
	seenPublicIDs[id] = ballot
	return nil
}
