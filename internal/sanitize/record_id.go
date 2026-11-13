package sanitize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

const ONE_MILLION = 1000000

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
	return "0x" + hex.EncodeToString(mac.Sum(nil))
}
