package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/AuburnCyber/dvsanitizer/internal/sanitize"
)

const (
	UNFINISHED_DIR_PREFIX = "SANITIZATION-UNFINISHED_"

	GEN_SEED_SIZE = 32 // in bytes

)

func createUnfinishedDir() string {
	unfinishedDirPath := filepath.Join(
		args.outputDir,
		UNFINISHED_DIR_PREFIX+time.Now().Format("2006-01-02T15-04-05"),
	)

	if err := os.Mkdir(unfinishedDirPath, 0755); err != nil {
		log.Fatalf("Unable to create directory for in-progress sanitization: %v", err)
	}

	return unfinishedDirPath
}

func main() {
	ParseCmd()

	key, err := loadKey(args)
	if err != nil {
		log.Fatal(err)
	}
	sanitize.InitializeForElection(key, args.electionID)

	var unfinishedDirPath string
	switch {
	case args.actionSanitizeCSV:
		validateSanitizeCSVFlags()
		unfinishedDirPath = createUnfinishedDir()
		SanitizeCSV(unfinishedDirPath)
	case args.actionSanitizeJSONZip:
		validateSanitizeJSONZipFlags()
		unfinishedDirPath = createUnfinishedDir()
		SanitizeJSONZip(unfinishedDirPath)
	case args.actionSanitizeTIFDir:
		validateSanitizeTIFDirFlags()
		unfinishedDirPath = createUnfinishedDir()
		SanitizeTIFDir(unfinishedDirPath)
	}

	// Now that we're finished, move everything out of the unfinished directory
	// into the actual output directory.
	entries, err := os.ReadDir(unfinishedDirPath)
	if err != nil {
		log.Fatalf("Unable to find contents of the unfinished-directory containing the post-sanitization files: %v", err)
	}
	for _, entry := range entries {
		unfinishedPath := filepath.Join(unfinishedDirPath, entry.Name())
		finishedPath := filepath.Join(args.outputDir, entry.Name())

		if err := os.Rename(unfinishedPath, finishedPath); err != nil {
			log.Fatalf("Unable to mark file as finished. unfinished-path: %q, finished-path: %q", unfinishedPath, finishedPath)
		}
	}
	if err := os.Remove(unfinishedDirPath); err != nil {
		log.Fatalf("Unable to delete now-empty unfinished-path: %v", err)
	}

}
