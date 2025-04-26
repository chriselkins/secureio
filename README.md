# secureio

**Secure, Atomic, Crash-Resistant, Hardened File Writing for Go**

[![Go Reference](https://pkg.go.dev/badge/github.com/chriselkins/secureio.svg)](https://pkg.go.dev/github.com/chriselkins/secureio)
[![Go CI](https://github.com/chriselkins/secureio/actions/workflows/go.yml/badge.svg)](https://github.com/chriselkins/secureio/actions/workflows/go.yml)

---

## ✨ Features

- **Atomic writes** using `O_TMPFILE` when available (no visible temp file)
- **Fallback to secure temp file + rename** if needed
- **Durability**: optional `fsync` on file and parent directory
- **Directory security hardened** using `openat2` when available
- **Prevents symlink, magiclink, and mountpoint attacks**
- **Root-aware mode**: verify parent directory ownership and safety
- **Strict root mode**: verify **all ancestor directories** up to `/`
- **User-defined ownership setting**: optionally set UID/GID after write
- **Mount crossing prevention (NoCrossDevice) enabled by default**
- **Designed for compliance-level security** on modern Linux systems

---

## 🔒 Secure-by-Default

`secureio` operates in a **secure-by-default** mode:

- Always attempts hardened directory opening using `openat2()` with strict flags.
- Prevents crossing mount points (`NoCrossDevice: true`) by default.
- Protects against symlink races, magic links, and bind mount attacks automatically.
- Ensures atomic, crash-safe file persistence without user needing to configure anything.

If you need to allow directory traversal across mount points (rare), set `NoCrossDevice: false` in `WriteOptions`.

> ⚠️ **Note for Docker and Kubernetes users**:  
> If your working directory crosses a mountpoint (e.g., a bind-mounted volume), you may need to set `NoCrossDevice: false` in `WriteOptions` to allow secureio to operate correctly.

---

## 🐧 Linux Kernel Requirements

| Feature | Requirement |
|:---|:---|
| Full `openat2` security | Linux 5.6+ |
| O_TMPFILE usage | Linux 3.11+ |
| Basic secure operation (fallback path) | Linux 2.6.16+ |

`secureio` automatically detects and falls back:
- If `openat2()` is not available (older kernel), falls back to `openat()`.
- If `O_TMPFILE` is not supported, falls back to temp file + `rename()`.

✅ No manual configuration needed — it adapts automatically.

---

## 🚀 Install

```bash
go get github.com/chriselkins/secureio
```

---

## 🔥 Usage

### Normal secure atomic write (non-root)

```go
import "github.com/chriselkins/secureio"

data := []byte("confidential data")
err := secureio.SecureAtomicWrite("/path/to/file.txt", data, 0600)
if err != nil {
    panic(err)
}
```

---

### Root-hardened atomic write (immediate parent check)

```go
import "github.com/chriselkins/secureio"

data := []byte("system configuration")
err := secureio.SecureAtomicWriteRoot("/etc/myapp/config.conf", data, 0644)
if err != nil {
    panic(err)
}
```

---

### Strict root-hardened atomic write (full ancestor verification)

```go
import "github.com/chriselkins/secureio"

data := []byte("compliance critical file")
err := secureio.SecureAtomicWriteRootStrict("/etc/secure/conf.d/critical.conf", data, 0644)
if err != nil {
    panic(err)
}
```

---

### Secure atomic write with user-defined ownership (UID/GID) and options

```go
import "github.com/chriselkins/secureio"

data := []byte("owned data")
opts := secureio.WriteOptions{
    Perm: 0644,
    UID: 1000,
    GID: 1000,
    Sync: true,
    VerifyAll: false,
    NoCrossDevice: true, // Prevent crossing mountpoints (enabled by default)
}
err := secureio.SecureAtomicWriteWithOptions("/path/to/file.txt", data, opts)
if err != nil {
    panic(err)
}
```

> **Note**: Set `NoCrossDevice: false` if you intentionally want to allow crossing mount points (rare case).

---

## 🛡 How It Works

1. Securely open the target **directory** using `openat2` with strict flags.
2. Create anonymous temp files with **`O_TMPFILE`**, or fall back to secure temp file creation with `O_CREAT|O_EXCL|O_NOFOLLOW`.
3. Write and optionally `fsync()` the temp file.
4. Atomically link or rename the file into final place.
5. Optionally set file ownership (UID/GID).
6. Optionally `fsync()` the parent directory for durability.
7. In root modes, verify parent or all ancestor directories for safe ownership and permissions.

✅ All directory openings are hardened against:
- **Symlink attacks**
- **Magiclink attacks**
- **Mountpoint crossing attacks** (via `NoCrossDevice`)

✅ All file writes are atomic, crash-safe, and permission-controlled.

---

## ✅ Goals

- Prevent **symlink races**
- Prevent **directory swap, bind mount, and procfs attacks**
- Guarantee **atomicity and durability** across crashes
- Allow **fine-grained post-write ownership control**
- Be **fast**, **safe**, and **drop-in simple** for modern Go developers

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Inspired by:
- Linux kernel security best practices
- Hardened filesystem writing techniques
- Projects like systemd, Kubernetes, and container runtimes

---

# ⚡ Future Ideas

- Add optional enforcement of RESOLVE_NO_XDEV per ancestor directory
- Allow customizable `sync` control per write operation
- Support structured ACL or xattrs post-write
- Windows fallback (with limited atomicity)

---

# 🌟 Why `secureio`?

Modern Go applications deserve modern, **secure**, **atomic**, and **correct** file persistence —  
**secureio** is built for developers who demand production-quality, compliance-grade filesystem safety.
