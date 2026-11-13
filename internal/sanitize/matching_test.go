package sanitize

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/AuburnCyber/dvsanitizer/internal/filefmt"
)

func TestMatchingAcrossFormats(t *testing.T) {
	InitializeForElection(testingKey, "GA|Example County|2026-11-03")
	rows, err := cleanCSVLines([][]string{{"1", "00001", "00002", "000003", "Alice"}})
	if err != nil {
		t.Fatal(err)
	}
	id := rows[0][3]
	if rows[0][4] != "Alice" {
		t.Fatal("vote content changed")
	}
	blob, err := filefmt.ParseJSON([]byte(`{"Version":"test","Sessions":[{"TabulatorId":1,"BatchId":2,"RecordId":3,"ImageMask":"00001_00002_000003_*.*"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	jsonID, err := sanitizeJSONSession(blob, 0)
	if err != nil || jsonID != id {
		t.Fatalf("JSON/CSV mismatch: %v", err)
	}
	mask, err := blob.GetSessionImageMask(0)
	if err != nil || mask != "00001_00002_"+id+"_*.*" {
		t.Fatalf("image mask mismatch: %s %v", mask, err)
	}
	for _, suffix := range []string{".tif", ".sha", "_1.tif", "_2.tif"} {
		path := buildCleanTIFSHAPath(filepath.Join("input", "00001_00002_000003"+suffix), "input", "output")
		if !strings.HasSuffix(path, "00001_00002_"+id+suffix) {
			t.Fatalf("image mismatch: %s", path)
		}
	}
}
