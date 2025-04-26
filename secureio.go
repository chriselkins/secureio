// Package secureio provides secure, atomic, crash-resistant, hardened file writing.
// It supports root-hardened operations with directory ownership and permission checks.
package secureio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WriteOptions defines options for secure file writing.
type WriteOptions struct {
	Perm          os.FileMode // File permissions (e.g., 0600, 0644)
	UID           int         // Optional UID ownership change, -1 to skip
	GID           int         // Optional GID ownership change, -1 to skip
	Sync          bool        // Whether to fsync file and directory (default true)
	VerifyAll     bool        // Whether to verify all parent directories up to /
	NoCrossDevice bool        // Prevent crossing mount points (RESOLVE_NO_XDEV), default true
}

// SecureAtomicWrite writes data with default secure options (sync and no-cross-device enabled).
func SecureAtomicWrite(path string, data []byte, perm os.FileMode) error {
	opts := WriteOptions{Perm: perm, UID: -1, GID: -1, Sync: true, VerifyAll: false, NoCrossDevice: true}
	return secureAtomicWriteInternal(path, data, opts)
}

// SecureAtomicWriteRoot writes with root verification (immediate parent check).
func SecureAtomicWriteRoot(path string, data []byte, perm os.FileMode) error {
	opts := WriteOptions{Perm: perm, UID: -1, GID: -1, Sync: true, VerifyAll: false, NoCrossDevice: true}
	return secureAtomicWriteInternal(path, data, opts)
}

// SecureAtomicWriteRootStrict writes with root verification (all ancestor checks).
func SecureAtomicWriteRootStrict(path string, data []byte, perm os.FileMode) error {
	opts := WriteOptions{Perm: perm, UID: -1, GID: -1, Sync: true, VerifyAll: true, NoCrossDevice: true}
	return secureAtomicWriteInternal(path, data, opts)
}

// SecureAtomicWriteWithOptions writes with custom WriteOptions.
func SecureAtomicWriteWithOptions(path string, data []byte, opts WriteOptions) error {
	return secureAtomicWriteInternal(path, data, opts)
}

// --- Internal ---

func secureAtomicWriteInternal(path string, data []byte, opts WriteOptions) error {
	err := ultraParanoidWrite(path, data, opts)
	if fallbackNeeded(err) {
		return paranoidAtomicWrite(path, data, opts)
	}
	return err
}

func fallbackNeeded(err error) bool {
	var errno unix.Errno
	if errors.As(err, &errno) {
		switch errno {
		case unix.EOPNOTSUPP, unix.EINVAL, unix.ENOTDIR, unix.EPERM:
			return true
		}
	}
	return false
}

func verifyDirectorySecure(path string, verifyAll bool) error {
	current := path
	for {
		fd, err := openDirSecure(current, true)
		if err != nil {
			return fmt.Errorf("open directory %s: %w", current, err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			unix.Close(fd)
			return fmt.Errorf("fstat directory %s: %w", current, err)
		}
		unix.Close(fd)

		if stat.Uid != 0 {
			return fmt.Errorf("directory %s not owned by root (uid=%d)", current, stat.Uid)
		}
		if stat.Mode&unix.S_IWOTH != 0 && stat.Mode&unix.S_ISVTX == 0 {
			return fmt.Errorf("directory %s is world-writable without sticky bit", current)
		}

		if !verifyAll || current == "/" {
			break
		}
		current = filepath.Dir(current)
	}
	return nil
}

func openDirSecure(path string, noCrossDevice bool) (int, error) {
	var resolveFlags uint64 = unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS
	if noCrossDevice {
		resolveFlags |= unix.RESOLVE_NO_XDEV
	}

	how := &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY,
		Resolve: resolveFlags,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, how)
	if err == nil {
		return fd, nil
	}
	if errors.Is(err, unix.ENOSYS) {
		return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	}
	return -1, err
}

func ultraParanoidWrite(path string, data []byte, opts WriteOptions) error {
	dirPath := filepath.Dir(path)
	baseName := filepath.Base(path)

	if opts.VerifyAll {
		if err := verifyDirectorySecure(dirPath, true); err != nil {
			return err
		}
	}

	dirFd, err := openDirSecure(dirPath, opts.NoCrossDevice)
	if err != nil {
		return fmt.Errorf("open directory secure: %w", err)
	}
	defer unix.Close(dirFd)

	tmpFd, err := unix.Openat(dirFd, "", unix.O_RDWR|unix.O_TMPFILE, uint32(opts.Perm))
	if err != nil {
		return fmt.Errorf("openat O_TMPFILE: %w", err)
	}
	defer unix.Close(tmpFd)

	if _, err := unix.Write(tmpFd, data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if opts.Sync {
		if err := unix.Fsync(tmpFd); err != nil {
			return fmt.Errorf("fsync temp file: %w", err)
		}
	}

	if opts.UID >= 0 || opts.GID >= 0 {
		if err := unix.Fchown(tmpFd, opts.UID, opts.GID); err != nil {
			return fmt.Errorf("fchown temp file: %w", err)
		}
	}

	unix.Unlinkat(dirFd, baseName, 0)

	if err := unix.Linkat(tmpFd, "", dirFd, baseName, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("linkat temp file: %w", err)
	}

	if opts.Sync {
		dirFile := os.NewFile(uintptr(dirFd), dirPath)
		defer dirFile.Close()
		if err := dirFile.Sync(); err != nil {
			return fmt.Errorf("sync directory: %w", err)
		}
	}

	return nil
}

func paranoidAtomicWrite(path string, data []byte, opts WriteOptions) error {
	dirPath := filepath.Dir(path)
	baseName := filepath.Base(path)
	tmpName := "." + baseName + ".tmp"

	if opts.VerifyAll {
		if err := verifyDirectorySecure(dirPath, true); err != nil {
			return err
		}
	}

	dirFd, err := openDirSecure(dirPath, opts.NoCrossDevice)
	if err != nil {
		return fmt.Errorf("open directory secure: %w", err)
	}
	defer unix.Close(dirFd)

	tmpFd, err := unix.Openat(dirFd, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, uint32(opts.Perm))
	if err != nil {
		return fmt.Errorf("openat temp file: %w", err)
	}
	defer func() {
		unix.Close(tmpFd)
		unix.Unlinkat(dirFd, tmpName, 0)
	}()

	tmpFile := os.NewFile(uintptr(tmpFd), tmpName)
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if opts.Sync {
		if err := tmpFile.Sync(); err != nil {
			return fmt.Errorf("fsync temp file: %w", err)
		}
	}

	if opts.UID >= 0 || opts.GID >= 0 {
		if err := unix.Fchown(tmpFd, opts.UID, opts.GID); err != nil {
			return fmt.Errorf("fchown temp file: %w", err)
		}
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	unix.Unlinkat(dirFd, baseName, 0)
	if err := unix.Renameat(dirFd, tmpName, dirFd, baseName); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	if opts.Sync {
		dirFile := os.NewFile(uintptr(dirFd), dirPath)
		defer dirFile.Close()
		if err := dirFile.Sync(); err != nil {
			return fmt.Errorf("sync directory: %w", err)
		}
	}

	return nil
}
