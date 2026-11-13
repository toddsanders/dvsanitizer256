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
		{0, 0, 0, "0xb951d88c26ad7cd4dfcb08cbc284c685c8d8ce0cfda173ffc816b2fa7d7c080b"},
		{1, 1, 1, "0xdd0c0356b6fd79f4de5d02e99e2bcd5598f05dbcf07ba5e51c16d6eb13cc0383"},
		{18, 18, 18, "0x06ffafea443509981015a4250429f6e28c46452fc924768e10c9387e321f74c4"},
		{31337, 31337, 31337, "0x909d7d6e5b50819b6947f73f8ca9a8a318dd857ff8efe1c31cb1a7d998b25382"},
		{ONE_MILLION - 1, ONE_MILLION - 1, ONE_MILLION - 1, "0x56b6e84e474d149ca590a467e3b0c6b06342c43e054f1c544e18980c83864063"},
		{ONE_MILLION, ONE_MILLION, ONE_MILLION, "0x6582a4f5c13b42189d6345ecc8d2ba07aad50688920d3f8fcfab2d30ce9f6c77"},
		{ONE_MILLION + 1, ONE_MILLION + 1, ONE_MILLION + 1, "0x315a5c8aa226cf1b75772bc6c2755bf925f864a39889c08ff5c193f0f7b7c7be"},
		{10*ONE_MILLION + 1, 10*ONE_MILLION + 1, 10*ONE_MILLION + 1, "0xaadc70351349631e3b54d8a8dd0bc2b213df5d6255d36763849ac3431ec3b832"},
		{1111, 2222, 33333, "0x1b29e40d0a9b8e9217298be9b983e5518fa5d8bf30abbb799b9ee1b7e45025f8"},
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
	if len(first) != 66 {
		t.Fatal("digest must not be truncated")
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
