package sanitize

import (
	"fmt"
	"testing"
)

var testingKey = []byte{
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
}

func Test_CreateCleanRecordID(t *testing.T) {
	// Known answers independently computed with Python hmac and struct.

	testcases := []struct {
		tabID    uint32
		batchID  uint32
		recordID uint32
		want     string
	}{
		{0, 0, 0, "0xb951d88c26ad7cd4dfcb08cbc284c685"},
		{1, 1, 1, "0xdd0c0356b6fd79f4de5d02e99e2bcd55"},
		{18, 18, 18, "0x06ffafea443509981015a4250429f6e2"},
		{31337, 31337, 31337, "0x909d7d6e5b50819b6947f73f8ca9a8a3"},
		{ONE_MILLION - 1, ONE_MILLION - 1, ONE_MILLION - 1, "0x56b6e84e474d149ca590a467e3b0c6b0"},
		{ONE_MILLION, ONE_MILLION, ONE_MILLION, "0x6582a4f5c13b42189d6345ecc8d2ba07"},
		{ONE_MILLION + 1, ONE_MILLION + 1, ONE_MILLION + 1, "0x315a5c8aa226cf1b75772bc6c2755bf9"},
		{10*ONE_MILLION + 1, 10*ONE_MILLION + 1, 10*ONE_MILLION + 1, "0xaadc70351349631e3b54d8a8dd0bc2b2"},
		{1111, 2222, 33333, "0x1b29e40d0a9b8e9217298be9b983e551"},
	}
	Initialize(testingKey)

	for _, tc := range testcases {
		t.Run(fmt.Sprintf("%d -- %d -- %d", tc.tabID, tc.batchID, tc.recordID), func(t *testing.T) {
			got := createCleanRecordID(tc.tabID, tc.batchID, tc.recordID)
			if got != tc.want {
				t.Errorf("incorrect output. got: %s, want: %s", got, tc.want)
			}
		})
	}
}

func TestElectionAndKeySeparation(t *testing.T) {
	InitializeForElection(testingKey, "GA|county|2026-11-03")
	first := createCleanRecordID(1, 2, 3)
	if len(first) != 34 {
		t.Fatal("public ID must contain exactly 128 bits")
	}
	InitializeForElection(testingKey, "GA|county|2026-11-04")
	if first == createCleanRecordID(1, 2, 3) {
		t.Fatal("election context ignored")
	}
	other := append([]byte(nil), testingKey...)
	other[0] ^= 1
	InitializeForElection(other, "GA|county|2026-11-03")
	if first == createCleanRecordID(1, 2, 3) {
		t.Fatal("key ignored")
	}
	InitializeForElection(testingKey, "GA|county|2026-11-03")
	if first != createCleanRecordID(1, 2, 3) {
		t.Fatal("IDs not reproducible")
	}
	if first == createCleanRecordID(2, 1, 3) || first == createCleanRecordID(1, 3, 2) {
		t.Fatal("ambiguous canonical identifier")
	}
}

func TestContextKnownAnswers(t *testing.T) {
	// Independently generated using Python hmac, hashlib and struct; context length is bytes.
	InitializeForElection(testingKey, "GA|county|2026-11-03")
	if got := createCleanRecordID(1, 2, 3); got != "0x04fbbb620aa81f736548980c49c74339" {
		t.Fatalf("context vector mismatch: %s", got)
	}
	InitializeForElection(testingKey, "GA|Comté|2026")
	if got := createCleanRecordID(1, 2, 3); got != "0x979e13c77f03575c8347b1d0c42f63f8" {
		t.Fatalf("context vector mismatch: %s", got)
	}
}

func TestIdentifierFieldsSeparated(t *testing.T) {
	InitializeForElection(testingKey, "GA|county|2026")
	original := createCleanRecordID(1, 2, 3)
	for _, ids := range [][3]uint32{{2, 2, 3}, {1, 3, 3}, {1, 2, 4}} {
		if createCleanRecordID(ids[0], ids[1], ids[2]) == original {
			t.Fatal("identifier field ignored")
		}
	}
}
