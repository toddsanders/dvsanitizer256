package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

func loadKey(a Args) ([]byte, error) {
	const message = "key must contain exactly 64 hexadecimal digits encoding 32 random bytes"
	if a.genSeed {
		key := make([]byte, GEN_SEED_SIZE)
		if _, err := rand.Read(key); err != nil {
			return nil, errors.New("could not generate key")
		}
		f, err := os.OpenFile(a.keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, errors.New("could not create private key file; it must not already exist")
		}
		_, err = f.WriteString(hex.EncodeToString(key) + "\n")
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, errors.New("could not save key; do not use incomplete key file")
		}
		return key, nil
	}
	encoded := a.seed
	if a.keyFile != "" {
		// Reject symlinks and broadly readable files rather than silently exposing keys.
		info, err := os.Lstat(a.keyFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("key file must be a regular private file with no group or other permissions")
		}
		data, err := os.ReadFile(a.keyFile)
		if err != nil {
			return nil, errors.New("could not read key file")
		}
		encoded = strings.TrimSpace(string(data))
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New(message)
	}
	return key, nil
}
