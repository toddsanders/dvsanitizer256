package sanitize

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCollisionRegistry(t *testing.T) {
	InitializeForElection(testingKey, "election")
	first := ballotIdentity{1, 2, 3}
	if err := registerPublicID("forced", first); err != nil {
		t.Fatal(err)
	}
	if err := registerPublicID("forced", first); err != nil {
		t.Fatal("repeated ballot rejected")
	}
	if err := registerPublicID("forced", ballotIdentity{1, 2, 4}); err == nil {
		t.Fatal("collision accepted")
	}
	if seenPublicIDs["forced"] != first {
		t.Fatal("collision overwrote original registry entry")
	}
	InitializeForElection(testingKey, "next election")
	if len(seenPublicIDs) != 0 {
		t.Fatal("initialization did not reset registry")
	}
	if err := registerPublicID("forced", ballotIdentity{1, 2, 4}); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRecordIDStopsOnCollision(t *testing.T) {
	if os.Getenv("DVSANITIZER_TEST_COLLISION") == "1" {
		InitializeForElection(testingKey, "election")
		id := createCleanRecordID(1, 2, 3)
		// Simulate a different ballot already owning the actual digest, so the
		// normal ID generation path must fail closed without weakening the HMAC.
		seenPublicIDs[id] = ballotIdentity{4, 5, 6}
		createCleanRecordID(1, 2, 3)
		os.Stdout.WriteString("UNSAFE_CONTINUATION")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCreateRecordIDStopsOnCollision$")
	cmd.Env = append(os.Environ(), "DVSANITIZER_TEST_COLLISION=1")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "identifier collision") || strings.Contains(string(output), "UNSAFE_CONTINUATION") {
		t.Fatalf("collision did not stop safely: %v %s", err, output)
	}
}
