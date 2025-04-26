package secureio

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func runningAsRoot() bool {
	return os.Geteuid() == 0
}

func supportsOTmpfile() bool {
	dir := os.TempDir()
	fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR, 0600)
	if err == nil {
		unix.Close(fd)
		return true
	}
	return false
}

func TestSecureAtomicWrite(t *testing.T) {
	if !supportsOTmpfile() {
		t.Skip("Skipping test: O_TMPFILE not supported on this system")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile.txt")
	content := []byte("hello world")

	if err := SecureAtomicWrite(path, content, 0600); err != nil {
		t.Fatalf("SecureAtomicWrite failed: %v", err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read back written file: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("File content mismatch: got %q want %q", string(read), string(content))
	}
}

func TestSecureAtomicWriteRoot(t *testing.T) {
	if !runningAsRoot() {
		t.Skip("Skipping test: not running as root")
	}
	if !supportsOTmpfile() {
		t.Skip("Skipping test: O_TMPFILE not supported on this system")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "rootfile.txt")
	content := []byte("secure data")

	if err := SecureAtomicWriteRoot(path, content, 0644); err != nil {
		t.Fatalf("SecureAtomicWriteRoot failed: %v", err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read back written file: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("File content mismatch: got %q want %q", string(read), string(content))
	}
}

func TestSecureAtomicWriteRootStrict(t *testing.T) {
	if !runningAsRoot() {
		t.Skip("Skipping test: not running as root")
	}
	if !supportsOTmpfile() {
		t.Skip("Skipping test: O_TMPFILE not supported on this system")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "strictfile.txt")
	content := []byte("strict secure data")

	if err := SecureAtomicWriteRootStrict(path, content, 0644); err != nil {
		t.Fatalf("SecureAtomicWriteRootStrict failed: %v", err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read back written file: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("File content mismatch: got %q want %q", string(read), string(content))
	}
}

func TestSecureAtomicWriteWithCustomOptions(t *testing.T) {
	if !supportsOTmpfile() {
		t.Skip("Skipping test: O_TMPFILE not supported on this system")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "customfile.txt")
	content := []byte("owned content")
	opts := WriteOptions{Perm: 0644, UID: os.Getuid(), GID: os.Getgid(), Sync: true, VerifyAll: false, NoCrossDevice: true}

	if err := SecureAtomicWriteWithOptions(path, content, opts); err != nil {
		t.Fatalf("SecureAtomicWriteWithOptions failed: %v", err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read back file: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("Content mismatch: got %q want %q", string(read), string(content))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("File permissions incorrect: got %o want 644", info.Mode().Perm())
	}
}

func TestSecureAtomicWriteSkipSync(t *testing.T) {
	if !supportsOTmpfile() {
		t.Skip("Skipping test: O_TMPFILE not supported on this system")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nonsyncfile.txt")
	content := []byte("fast write")
	opts := WriteOptions{Perm: 0600, UID: -1, GID: -1, Sync: false, VerifyAll: false, NoCrossDevice: true}

	if err := SecureAtomicWriteWithOptions(path, content, opts); err != nil {
		t.Fatalf("SecureAtomicWriteWithOptions (no sync) failed: %v", err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read back file: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("Content mismatch: got %q want %q", string(read), string(content))
	}
}

func TestSecureAtomicWriteWithInterruptSimulated(t *testing.T) {
	if !supportsOTmpfile() {
		t.Skip("Skipping test: O_TMPFILE not supported on this system")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "interruptfile.txt")
	tmpPath := filepath.Join(dir, ".interruptfile.txt.tmp")
	content := []byte("final correct content")

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatalf("Failed to manually create temp file: %v", err)
	}
	f.Write([]byte("partial data"))
	f.Close()

	opts := WriteOptions{Perm: 0600, UID: -1, GID: -1, Sync: true, VerifyAll: false, NoCrossDevice: true}
	if err := SecureAtomicWriteWithOptions(path, content, opts); err != nil {
		t.Fatalf("SecureAtomicWriteWithOptions after simulated crash failed: %v", err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read file after crash recovery: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("Content mismatch after crash recovery: got %q want %q", string(read), string(content))
	}
}

func TestVerifyDirectorySecureFailsOnBadOwnership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badperm")
	os.Mkdir(path, 0777) // world-writable without sticky bit

	err := verifyDirectorySecure(path, true)
	if err == nil {
		t.Fatalf("Expected verifyDirectorySecure to fail but it passed")
	}
}

func TestSecureAtomicWriteRootStrictVerification(t *testing.T) {
	if !runningAsRoot() {
		t.Skip("Skipping test: not running as root")
	}
	if !supportsOTmpfile() {
		t.Skip("Skipping test: O_TMPFILE not supported on this system")
	}
	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	os.Mkdir(subdir, 0755)
	path := filepath.Join(subdir, "strictfile.txt")
	content := []byte("strictly secure")

	opts := WriteOptions{Perm: 0644, UID: -1, GID: -1, Sync: true, VerifyAll: true, NoCrossDevice: true}

	if err := SecureAtomicWriteWithOptions(path, content, opts); err != nil {
		t.Fatalf("SecureAtomicWriteWithOptions strict failed: %v", err)
	}

	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read back strict file: %v", err)
	}
	if string(read) != string(content) {
		t.Fatalf("Strict file content mismatch: got %q want %q", string(read), string(content))
	}
}
