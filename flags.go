package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/AuburnCyber/dvsanitizer/internal/safety"
)

type Args struct {
	seed                  string
	keyFile               string
	electionID            string
	genSeed               bool
	inputPath             string
	outputDir             string
	actionSanitizeCSV     bool
	actionSanitizeJSONZip bool
	actionSanitizeTIFDir  bool
}

var args Args

func ParseCmd() {
	flag.StringVar(&args.keyFile, "key-file", "", "Private file containing a 64-digit hexadecimal key; created exclusively with --gen-seed.")
	flag.StringVar(&args.electionID, "election-id", "", "Stable election and jurisdiction context; identical for matching CVRs and images.")
	flag.StringVar(&args.inputPath, "input", "",
		"The file/directory to read dirty data from (type depends on instruction of what to sanitize).",
	)
	flag.StringVar(&args.outputDir, "output-dir", "",
		"The file/directory to write cleaned data to (type depends on instruction of what to sanitize).",
	)
	flag.StringVar(&args.seed, "seed", "",
		"Deprecated: a 64-digit hexadecimal random key. Prefer --key-file to avoid command-line exposure.",
	)
	flag.BoolVar(&args.genSeed, "gen-seed", false,
		"Generate a cryptographically random 256-bit key in --key-file, without printing it.",
	)
	flag.BoolVar(&args.actionSanitizeCSV, "sanitize-csv", false,
		"Sanitize the input .CSV-format CVR file (--input) and write it to the output directory (--output-dir). "+
			"The cleaned CSV's filename is unchanged.")
	flag.BoolVar(&args.actionSanitizeJSONZip, "sanitize-json-zip", false,
		"Sanitize the input zipped-JSON CVR file (--input) and write it to the output directory (--output-dir). "+
			"The cleaned ZIP's filename is unchanged.",
	)
	flag.BoolVar(&args.actionSanitizeTIFDir, "sanitize-tif-dir", false,
		"Recursively walk the input directory (--input); sanitize and copy any .tif ballot images or .sha hash files to the output directory (--output-dir) (any other files in the input directory are omitted).",
	)

	flag.Parse()

	// Make sure only 1 action-flag is given
	actionCount := 0
	if args.actionSanitizeCSV {
		actionCount += 1
	}
	if args.actionSanitizeJSONZip {
		actionCount += 1
	}
	if args.actionSanitizeTIFDir {
		actionCount += 1
	}
	if actionCount == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if actionCount > 1 {
		log.Fatalf("You can only supply a single instruction (i.e., --sanitize-tif-dir OR --sanitize-csv but not both).")
	}

	if args.electionID == "" {
		log.Fatal("You must supply --election-id, including election and jurisdiction.")
	}
	if args.genSeed && (args.keyFile == "" || args.seed != "") {
		log.Fatal("--gen-seed requires --key-file and cannot be combined with --seed.")
	}
	if !args.genSeed && ((args.keyFile == "") == (args.seed == "")) {
		log.Fatal("Supply exactly one of --key-file or --seed.")
	}

	// Generic validation for all other flags (specific validation handled in own function).
	switch {
	case args.inputPath == "":
		log.Fatalf("You must supply an input path (--input).")
	case !safety.PathExists(args.inputPath):
		log.Fatalf("Input path does not exist.")
	case args.outputDir == "":
		log.Fatalf("You must supply an output directory (--output-dir).")
	case !safety.IsDir(args.outputDir):
		log.Fatalf("Output directory (--output-dir) is not a directory.")
	}

	// Make everything significantly more predictable to handle and debug.
	var err error
	args.outputDir, err = filepath.Abs(args.outputDir)
	if err != nil {
		log.Fatalf("Try a different output directory (--output-dir) as an error was encountered validating command line arguments: %v", err)
	}
	args.inputPath, err = filepath.Abs(args.inputPath)
	if err != nil {
		log.Fatalf("An error was encountered validating the input-path (--input-path): %v", err)
	}
}

func validateSanitizeTIFDirFlags() {
	flagsOK := true
	switch {
	case !safety.IsDir(args.inputPath):
		flagsOK = false
	}
	if !flagsOK {
		log.Fatalf("When using --sanitize-tif-dir action, --input and --output-dir must be directories")
	}

	if args.inputPath == args.outputDir {
		log.Fatalf("Refusing to execute as input and output directory are identical.")
	}

	dirEntries, err := os.ReadDir(args.outputDir)
	if err != nil {
		log.Fatalf("An error was encountered trying to access the output directory: %v", err)
	}
	if len(dirEntries) != 0 {
		log.Fatalf("The output directory is not empty. Refusing to execute due to the possibility of mixing sanitized and unsanitized data.")
	}

}

func validateSanitizeCSVFlags() {
	flagsOK := true
	switch {
	case !safety.IsFile(args.inputPath):
		flagsOK = false
	case filepath.Ext(args.inputPath) != ".csv":
		flagsOK = false
	}
	if !flagsOK {
		log.Fatalf("When using --sanitize-csv instruction, --input must be a CSV file (.csv) and --output-dir must be a directory.")
	}

	_, inOutFilename := filepath.Split(args.inputPath)
	if safety.PathExists(filepath.Join(args.outputDir, inOutFilename)) {
		log.Fatalf("Refusing to execute as output-file would overwrite an existing file.")
	}
}

func validateSanitizeJSONZipFlags() {
	flagsOK := true
	switch {
	case !safety.IsFile(args.inputPath):
		flagsOK = false
	case filepath.Ext(args.inputPath) != ".zip":
		flagsOK = false
	}

	if !flagsOK {
		log.Fatalf("When using --sanitize-json-zip instruction, --input must be a ZIP file (.zip) and --output-dir must be a directory.")
	}

	_, inOutFilename := filepath.Split(args.inputPath)
	if safety.PathExists(filepath.Join(args.outputDir, inOutFilename)) {
		log.Fatalf("Refusing to execute as output-file would overwrite an existing file.")
	}
}
