pnut.toml(5)

# NAME

pnut.toml - pnut sandbox configuration file

# DESCRIPTION

The *pnut* sandbox is configured entirely through a TOML file passed via
*pnut --config*. This page documents every section and field.

Fields marked with a default value are optional. Fields marked *required* must
be present when their containing section is used.

# SECTIONS

## [sandbox]

General sandbox settings. All fields are optional.

*hostname* (string)
	Hostname visible inside the sandbox. Requires *namespaces.uts = true* or
	validation fails. Default: inherit host hostname.

*cwd* (string)
	Working directory for the sandboxed process. Default: */*.

*mode* (string)
	Execution mode.

	*once*
		(default) Fork via *clone3*; parent supervises child and propagates
		exit status.

	*execve*
		Calling process unshares and exec's directly; no supervising parent.

*new_session* (bool)
	Call *setsid*(2) to create a new session and disconnect from the
	controlling terminal. Mitigates CVE-2017-5226. Default: *true*.

*die_with_parent* (bool)
	Set PR_SET_PDEATHSIG so the child is killed if the parent exits.
	Default: *true*.

*argv0* (string)
	Override argv[0] for the command. Default: use the command path as
	argv[0].

*no_new_privs* (bool)
	Set PR_SET_NO_NEW_PRIVS via *prctl*(2) before exec. Prevents *execve*
	from granting privileges (setuid binaries, file capabilities). Required
	for unprivileged seccomp filter installation. Default: *true*.

*disable_tsc* (bool)
	Disable RDTSC and RDTSCP instructions via *prctl*(2) (PR_SET_TSC).
	x86/x86_64 only; causes SIGSEGV on RDTSC. Default: *false*.

*dumpable* (bool)
	Set PR_SET_DUMPABLE. When *false*, prevents same-UID ptrace and
	*/proc/<pid>/mem* access from outside the sandbox. Default: *false*.

*forward_signals* (bool)
	Forward signals received by the supervisor to the sandboxed child.
	When *false*, any signal to the supervisor kills the child with SIGKILL.
	Only applies in *once* mode. Default: *true*.

## [namespaces]

Controls which Linux namespaces are created. All fields are booleans.

*user* (bool)
	User namespace. Required for unprivileged sandboxing. Default: *true*.

*pid* (bool)
	PID namespace. Child becomes PID 1. Default: *true*.

*mount* (bool)
	Mount namespace. Required for filesystem isolation via *pivot_root*(2).
	Default: *true*.

*uts* (bool)
	UTS namespace. Required if *sandbox.hostname* is set. Default: *false*.

*ipc* (bool)
	IPC namespace. Isolates System V IPC and POSIX message queues.
	Default: *false*.

*net* (bool)
	Network namespace. When *true*, the sandbox gets an isolated network stack
	with only loopback. When *false*, it inherits the host network.
	Default: *false*.

*cgroup* (bool)
	Cgroup namespace. Default: *false*.

*time* (bool)
	Time namespace. Virtualizes CLOCK_MONOTONIC and CLOCK_BOOTTIME. Requires
	kernel >= 5.6. Default: *false*.

*allow_nested_userns* (bool)
	Allow the sandboxed process to create nested user namespaces. When
	*false*, seccomp rules deny *clone3* (ENOSYS), *clone* and *unshare*
	with namespace flags. Prevents sandbox escape via namespace reshaping.
	Default: *false*.

## [[mount]]

An ordered array of filesystem mount operations. Each entry is a TOML
array-of-tables element. Mounts are applied in order before *pivot_root*.

Each entry must specify exactly one of: *bind*, *type*, or *content*.

*src* (string)
	Source path on the host. Required for bind mounts.

*dst* (string)
	Destination path inside the sandbox. *Required*.

*bind* (bool)
	Perform a recursive bind mount (MS_BIND | MS_REC). Default: *false*.

*read_only* (bool)
	Remount read-only (MS_RDONLY). Default: *false*.

*type* (string)
	Filesystem type for a fresh mount (e.g., *tmpfs*, *proc*, *mqueue*).
	Mutually exclusive with *bind* and *content*.

*proc_subset* (string)
	Proc mount only. The *subset=* mount option. Valid values: *"pid"*.
	When set to *"pid"* (default), only PID-related entries are visible;
	*/proc/sys*, */proc/kallsyms*, */proc/net*, etc. are hidden.
	Set to *null* to mount full proc. Requires kernel >= 5.8.

*hidepid* (string)
	Proc mount only. The *hidepid=* mount option. Valid values:
	*"invisible"* (default), *"hidden"*, *"visible"*, or numeric
	*"0"*, *"1"*, *"2"*. Controls visibility of other processes'
	*/proc/<pid>* directories.

*content* (string)
	Inline file content. A regular file is created at *dst* with this content.
	Mutually exclusive with *bind* and *type*.

*size* (integer)
	Size limit in bytes for *tmpfs* mounts. Only meaningful when
	*type = "tmpfs"*.

*perms* (string)
	Octal permission string for *tmpfs* mounts (e.g., "0700"). Only
	meaningful when *type = "tmpfs"*.

## [uid_map]

Maps a host UID range into the sandbox. Typically required when
*namespaces.user = true* to give the sandboxed process a valid UID.

*inside* (integer)
	UID inside the sandbox. Default: *0*.

*outside* (integer)
	Host UID to map from. *Required*.

*count* (integer)
	Number of consecutive UIDs to map. Default: *1*.

## [gid_map]

Maps a host GID range into the sandbox. Same schema as *[uid_map]*.

*inside* (integer)
	GID inside the sandbox. Default: *0*.

*outside* (integer)
	Host GID to map from. *Required*.

*count* (integer)
	Number of consecutive GIDs to map. Default: *1*.

## [env]

Environment variable policy for the sandboxed process.

*clear* (bool)
	Clear all inherited environment variables before applying *set* and
	*keep*. Default: *false*.

*set* (table)
	Key-value pairs to set or override. Applied after *clear* and *keep*.

	```
	[env]
	clear = true

	[env.set]
	PATH = "/usr/bin:/bin"
	HOME = "/home/sandbox"
	```

*keep* (array of strings)
	Host environment variables to preserve when *clear = true*. Ignored when
	*clear = false* (all variables are already inherited).

	```
	[env]
	clear = true
	keep = ["TERM", "LANG"]
	```

## [rlimits]

Resource limits applied via *setrlimit*(2). All fields are optional; omitted
fields leave the inherited limit unchanged. For fields ending in *\_mb*, the
value is in mebibytes and is converted to bytes internally.

*nofile* (integer)
	RLIMIT_NOFILE. Maximum number of open file descriptors.

*nproc* (integer)
	RLIMIT_NPROC. Maximum number of processes for the real user ID.

*fsize_mb* (integer)
	RLIMIT_FSIZE. Maximum file size in MiB.

*stack_mb* (integer)
	RLIMIT_STACK. Maximum stack size in MiB.

*as_mb* (integer)
	RLIMIT_AS. Maximum virtual memory (address space) in MiB.

*core_mb* (integer)
	RLIMIT_CORE. Maximum core dump size in MiB.

*cpu* (integer)
	RLIMIT_CPU. Maximum CPU time in seconds.

## [landlock]

Landlock LSM filesystem access control. Restricts filesystem access beyond
what mount namespace isolation provides. All fields are arrays of path strings.

*allowed_read* (array of strings)
	Paths where read access is permitted.

*allowed_write* (array of strings)
	Paths where write access is permitted.

*allowed_execute* (array of strings)
	Paths where execute access is permitted.

## [capabilities]

Linux capability management. All capabilities are dropped by default.

*keep* (array of strings)
	Capabilities to retain (e.g., CAP_NET_BIND_SERVICE, CAP_SYS_PTRACE).
	Names are validated at build time.

## [fd]

File descriptor policy.

*close_fds* (bool)
	Close all file descriptors >= 3 that are not explicitly mapped.
	Default: *true*.

*map* (array of tables)
	Explicit FD remappings. Each entry has:

	*src* (integer)
		Source file descriptor. *Required*.

	*dst* (integer)
		Destination file descriptor. *Required*. Must be unique across all
		mappings.

## [run]

Default command to execute if none is given on the command line. CLI arguments
(after *--*) take priority over this section.

*path* (string)
	Binary path to execute. *Required*.

*args* (array of strings)
	Arguments to pass to the command. Default: empty.

*argv0* (string)
	Override argv[0] for the command. Overrides *sandbox.argv0* when the
	*[run]* section command is used. Default: use *path* as argv[0].

## seccomp_policy, seccomp_policy_file (top-level)

Seccomp-bpf syscall filtering using a Kafel-inspired DSL. These two fields are
mutually exclusive; specifying both is an error.

*seccomp_policy* (string)
	Inline seccomp policy string.

	```
	seccomp_policy = """
	POLICY default {
	  ALLOW { read, write, exit, exit_group, brk, mmap, close }
	  DENY {}
	}
	USE default DEFAULT KILL
	"""
	```

*seccomp_policy_file* (string)
	Path to a file containing the seccomp policy.

# EXAMPLES

A comprehensive configuration:

```
[sandbox]
hostname = "box"
cwd = "/home/user"
mode = "once"
new_session = true
die_with_parent = true

[namespaces]
user = true
pid = true
mount = true
uts = true
ipc = true
net = true

[uid_map]
inside = 0
outside = 1000
count = 1

[gid_map]
inside = 0
outside = 1000
count = 1

[[mount]]
src = "/usr"
dst = "/usr"
bind = true
read_only = true

[[mount]]
dst = "/tmp"
type = "tmpfs"
size = 67108864
perms = "1777"

[[mount]]
dst = "/proc"
type = "proc"

[[mount]]
dst = "/etc/hostname"
content = "sandbox"

[env]
clear = true
keep = ["TERM", "LANG"]

[env.set]
PATH = "/usr/bin:/bin"
HOME = "/home/user"

[rlimits]
nofile = 256
nproc = 64
as_mb = 512

[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/etc"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/bin"]

[capabilities]
keep = []

[fd]
close_fds = true

[run]
path = "/bin/sh"
args = ["-i"]
```

# SEE ALSO

*pnut*(1), *toml*(5), *setrlimit*(2), *seccomp*(2), *landlock*(7),
*capabilities*(7)
