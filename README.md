# pnut

*pnut* (pronounced "peanut") is a lightweight Linux sandbox that runs
entirely without root, setuid, or special capabilities.

The name is a nod to [bubblewrap](https://github.com/containers/bubblewrap):
both are packing material.

[![crates.io](https://img.shields.io/crates/v/pnut.svg)](https://crates.io/crates/pnut)
[![docs.rs](https://img.shields.io/docsrs/pnut)](https://docs.rs/pnut)

## What it does

pnut confines processes using Linux kernel isolation primitives, with no root
privileges, no setuid binaries, and no special capabilities required.

- **User namespaces** — the only entry point. All isolation is bootstrapped
  from `CLONE_NEWUSER`, so any unprivileged user can create a sandbox.
- **Namespace isolation** — PID, mount, network, UTS, IPC, cgroup, and time
  namespaces via `clone3` or `unshare`.
- **Filesystem confinement** — bind mounts, tmpfs overlays, `pivot_root`, and
  inline file content, all described declaratively in TOML.
- **Seccomp-bpf** — Kafel DSL for writing syscall filter policies with argument
  matching, named policies, and composable `USE` directives.
- **Landlock** — LSM-based filesystem access control, restricting file access
  beyond what mount namespaces provide.
- **Capability dropping** — all capabilities dropped by default, with explicit
  keep-list.
- **Resource limits** — rlimit enforcement for memory, open files, processes,
  CPU time, and file sizes.
- **File descriptor control** — close-on-exec for inherited fds, explicit
  fd remapping.

## Why not bubblewrap?

bubblewrap is excellent. pnut explores a different point in the design space:

- **Declarative TOML config** instead of long CLI flag chains.
- **Deeper LSM integration** — seccomp-bpf policies as a first-class DSL,
  plus Landlock filesystem restrictions.
- **Written in Rust** — memory safety without a runtime.
- **Two execution modes** — `clone3`-based (parent supervises child) and
  `unshare`+`execve` (caller becomes the sandbox).

## Requirements

- Linux >= 5.11
- Unprivileged user namespaces enabled (`kernel.unprivileged_userns_clone = 1`)
- Rust 2024 edition (stable toolchain)

## Install

```
cargo install pnut-cli
```

## Usage

```
pnut --config sandbox.toml -- <command> [args...]
```

### Example

Create a minimal config file (`minimal.toml`):

```toml
[namespaces]
user = true
pid = true
mount = true

[uid_map]
inside = 0
outside = 1000    # replace with your UID (id -u)
count = 1

[gid_map]
inside = 0
outside = 1000    # replace with your GID (id -g)
count = 1
```

Run a command in the sandbox:

```
pnut --config minimal.toml -- /bin/echo hello
```

The sandboxed process runs as UID 0 inside the namespace (mapped from your
real UID) and is PID 1 in its own PID namespace.

See [`examples/full.toml`](examples/full.toml) for a comprehensive annotated
config, or the man pages (`pnut(1)` and `pnut.toml(5)`) for full documentation.

## Crates

| Crate | Description |
|-------|-------------|
| [`pnut`](https://crates.io/crates/pnut) | Library for building and running sandboxes programmatically |
| [`pnut-cli`](https://crates.io/crates/pnut-cli) | CLI binary (`pnut`) driven by TOML config files |
| [`kafel`](https://crates.io/crates/kafel) | Standalone seccomp-bpf policy compiler (Kafel DSL to BPF) |

## License

Apache-2.0. See [LICENSE](LICENSE).
