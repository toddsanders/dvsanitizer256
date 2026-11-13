package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	key, err := loadKey(Args{genSeed: true, keyFile: path})
	if err != nil || len(key) != 32 {
		t.Fatalf("generation failed: %v", err)
	}
	again, err := loadKey(Args{keyFile: path})
	if err != nil || !bytes.Equal(key, again) {
		t.Fatal("key roundtrip failed")
	}
	if _, err := loadKey(Args{genSeed: true, keyFile: path}); err == nil {
		t.Fatal("overwrote key")
	}
	if _, err := loadKey(Args{seed: "not a random key"}); err == nil {
		t.Fatal("accepted invalid key")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey(Args{keyFile: path}); err == nil {
		t.Fatal("accepted public key file")
	}
}
