# Roadmap

What's next for pnut, roughly in priority order.

## Done (recent)

- **User `/dev/*` bind-mounts survive `setup_dev`** — `setup_dev` now runs
  before the user mount loop so bind-mounts under `/dev` (e.g. `/dev/nvidia0`
  for CUDA) land on top of the managed `/dev` tmpfs instead of being silently
  shadowed by it.
- **`proc_subset = "none"` / `hidepid = "none"`** — both config fields now
  accept `"none"` as an explicit opt-out, letting users mount full `/proc`
  (for e.g. `/proc/driver/nvidia`) without bind-mounting host `/proc`. The
  misleading `null` reference in `examples/full.toml` and `pnut.toml(5)` is
  fixed.
- **Seccomp diagnostic rendering** — kafel errors now carry byte-offset spans
  threaded from pest through the AST and resolver. `kafel::render_diagnostic`
  produces rustc-style output with `--> file:line:col`, a source snippet, and
  a caret under the offending token. Wired into pnut's seccomp compile path
  so CLI users see exactly where a broken policy went wrong.
- **New mount API** — `fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`/
  `mount_setattr` for fd-based VFS construction. Eliminates TOCTOU races,
  provides atomic flag application, and fd-relative tree construction.
  `pivot_root(".", ".")` via fchdir.
- **pnut-child integration** — `#![no_std]` child runtime is the sole
  post-clone3 executor. Zero heap allocation after fork. Safe for library
  use in multi-threaded processes.
- **Structured child failure reporting** — `Error::ChildSetup` with
  `ChildStage`, errno, detail, and human-readable message. Library users
  get programmatic access to child failures instead of `Ok(126)`.
- **Module consolidation** — config types unified into `config.rs`,
  `TryFrom<SandboxBuilder> for Sandbox`, `MountEntry` as proper enum,
  namespace/idmap/seccomp folded into `sandbox/`.
- **Signal forwarding** — pidfd + signalfd poll loop for race-free
  supervision, `pidfd_send_signal` for forwarding.
- **Landlock ABI V2-V5** — refer, truncate, network (bind/connect),
  ioctl_dev.
- **PR_SET_MDWE** — W^X enforcement opt-in.
- **Hardened proc** — `subset=pid`, `hidepid=invisible` defaults.

## Now

### Bugs (from first-use feedback)

- **`allowed_connect = []` means "unrestricted", not "deny all".** Silent
  network-egress footgun: the natural reading of an empty allowlist is
  deny-all, but today it disables the filter entirely. Fix: flip semantics
  so empty = deny all, with an explicit `unrestricted_connect = true` (or
  `Option<Vec<u16>>` where absent = unrestricted, `Some([])` = deny). Audit
  `allowed_bind` for the same issue.

### Other

- **Man page installation** — `pnut(1)` and `pnut.toml(5)` are written (scdoc
  source in `doc/`); need an install story (`make install` or similar).
- **Landlock port ranges** — `allowed_bind` and `allowed_connect` currently
  take single ports only. Support range syntax (e.g. `"8000-8999"`) expanded
  to individual rules.

## Next

### Hardening

- **Landlock ABI 6+** — abstract unix socket and signal scoping (6.12+).

### Supervision

- **PR_SET_CHILD_SUBREAPER** — reap orphaned grandchildren when `pid = false`
  (no PID namespace). When `pid = true` (default), the kernel reparents orphans
  to PID 1 inside the namespace.

### Usability

- **High-level path access declarations** — a single directive like
  `allow_read = ["/data"]` that auto-configures bind mount + Landlock allowlist.
- **Landlock errors should name the failing path.** Today a bad path in
  `allowed_read`/`write`/`execute` surfaces as `No such file or directory
  (os error 2)` with no indication which path triggered it. Debugging means
  commenting paths out one at a time. Include the path string in the error,
  or log each rule as it's added.
- **`pnut --help` should point at the schema.** Add a "see `examples/full.toml`
  or `man 5 pnut.toml`" line so first-time users aren't guessing at section
  names.
- **`--verbose` / tracing mode.** Trace the mount plan, Landlock rules
  applied, and child exit cause. When a sandboxed command dies at startup,
  pnut exits with the same code and no extra context — combined with silent
  fallbacks in downstream tools (e.g. CUDA → CPU), debugging takes longer
  than it should.
- **Testing on more kernels** — CI coverage across kernel versions (5.11,
  5.15 LTS, 6.x).

## Later

### Unprivileged

- **mseal(2)** — opt-in memory sealing (6.10+).
- **Seccomp USER_NOTIF** — syscall brokering via supervisor IPC.
- **ID-mapped mounts** — `mount_setattr` for UID/GID translation (5.12+).
- **Detached mount tree** — build entire mount tree in detached tmpfs,
  attach only at pivot_root time.

### Privileged

- **Cgroup v2 resource limits** — memory, CPU, PID, IO limits.
- **Privileged mode** — optional elevated-capability mode for veth
  networking, real UID transitions, device control.
- **Network policy** — egress filtering via nftables with veth plumbing.
- **Filesystem image mounts** — squashfs/erofs images as sandbox roots.

## Non-goals

- OCI runtime compatibility — pnut is not a replacement for runc/crun.
- Image management — pulling, layering, or storing container images.
- Orchestration — no daemon, no API server, no pod concept.
