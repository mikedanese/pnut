# Roadmap

What's next for pnut, roughly in priority order.

## Now

- **Man page installation** — `pnut(1)` and `pnut.toml(5)` are written (scdoc
  source in `doc/`); need an install story (`make install` or similar).

## Next

### Hardening

- **Landlock ABI V2–V5** — currently hardcoded to ABI V1. Feature-detect the
  kernel's ABI and opportunistically enable: rename/link control (V2, 5.19),
  truncation control (V3, 6.2), TCP port policy (V4, 6.7), device ioctl
  mediation (V5, 6.10). The `landlock` crate already supports ABI negotiation.

### Supervision

- **PR_SET_CHILD_SUBREAPER** — reap orphaned grandchildren when `pid = false`
  (no PID namespace). When `pid = true` (default), the kernel reparents orphans
  to PID 1 inside the namespace. Needs careful design for library callers
  where `waitpid(-1)` can steal unrelated children.

### Usability

- **Seccomp policy usability** — better error messages when a policy fails to
  compile, with source location and context.
- **Config validation improvements** — catch more mistakes at build time
  (e.g., mount dst conflicts, missing library paths for bind mounts).
- **High-level path access declarations** — a single directive like
  `allow_read = ["/data"]` that auto-configures the underlying layers: bind
  mount, Landlock allowlist, and seccomp policy (if path-relevant). Today you
  have to configure `[[mount]]`, `[landlock]`, and potentially seccomp
  separately for each path. This is the most common source of misconfiguration.
- **Testing on more kernels** — CI coverage across kernel versions (5.11,
  5.15 LTS, 6.x) to catch namespace behavior differences.

## Later

### Unprivileged

- **PR_SET_MDWE** — opt-in W^X enforcement (6.3+). Deny write+execute
  mappings. Breaks JIT workloads, so must be opt-in.
- **Landlock TCP port policy** — with ABI V4, unprivileged per-port
  bind/connect allowlists without requiring full network namespace or
  privileged veth setup.
- **Landlock ABI 6+** — abstract unix socket and signal scoping (6.12+).
- **mseal(2)** — opt-in memory sealing (6.10+). Prevent VMA manipulation
  after setup.
- **New mount API** — `fsopen`/`fsconfig`/`fsmount` for TOCTOU-free VFS
  construction. Large implementation effort.
- **Seccomp USER_NOTIF** — syscall brokering via supervisor IPC. Powerful
  but expands trusted computing base. First use case: single-execve
  enforcement — approve the first `execve` after filter installation via
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, deny subsequent ones. Currently pnut
  blanket-allows execve in the filter.
- **ID-mapped mounts** — `mount_setattr` for UID/GID translation on shared
  directories (5.12+).

### Privileged

- **Cgroup v2 resource limits** — memory, CPU, PID, and IO limits.
  Initially via delegated cgroup subtrees (unprivileged when the host
  pre-delegates). Full cgroup management in privileged mode.
  See [PRIVILEGED.md](PRIVILEGED.md).
- **Privileged mode** — optional elevated-capability mode for features with
  no unprivileged equivalent: veth networking, real UID transitions, device
  control, nested userns denial via sysctl.
  See [PRIVILEGED.md](PRIVILEGED.md).
- **Network policy** — egress filtering via nftables when privileged mode
  provides veth/macvlan plumbing.
- **Filesystem image mounts** — mount squashfs/erofs images as sandbox roots.

## Non-goals

- OCI runtime compatibility — pnut is not a replacement for runc/crun.
- Image management — pulling, layering, or storing container images.
- Orchestration — no daemon, no API server, no pod concept.
