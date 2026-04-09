use crate::error::{BuildError, Error, Stage};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::prctl;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::ffi::CString;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::io::OwnedFd;
use std::path::{Path, PathBuf};

use crate::caps as capmod;
use crate::caps::Config as CapsConfig;
use crate::env;
use crate::env::Config as EnvConfig;
use crate::fd;
use crate::fd::Config as FdConfig;
use crate::idmap;
use crate::idmap::Map as IdMap;
use crate::landlock;
use crate::landlock::Config as LandlockConfig;
use crate::mount;
use crate::namespace;
use crate::net;
use crate::rlimit;
use crate::rlimit::Config as RlimitsConfig;
use crate::seccomp;

/// Run mode for the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    #[default]
    Once,
    Execve,
}

/// What to execute inside the sandbox.
///
/// `args[0]` is the binary path. `argv0` optionally overrides what the
/// child sees as argv\[0\] (defaults to args\[0\]).
#[derive(Debug, Default)]
pub struct Command {
    pub(crate) args: Vec<String>,
    pub(crate) argv0: Option<String>,
    pub(crate) cwd: String,
}

impl Command {
    fn new() -> Self {
        Self {
            args: Vec::new(),
            argv0: None,
            cwd: "/".to_string(),
        }
    }

    fn has_command(&self) -> bool {
        !self.args.is_empty()
    }
}

/// Process lifecycle options applied inside the sandbox.
#[derive(Debug)]
pub struct ProcessOptions {
    pub new_session: bool,
    pub die_with_parent: bool,
    /// Set `PR_SET_NO_NEW_PRIVS` before exec. Prevents `execve` from
    /// granting privileges (setuid, file capabilities). Required for
    /// unprivileged seccomp filter installation. Default: `true`.
    pub no_new_privs: bool,
    /// Disable RDTSC/RDTSCP instructions (x86/x86_64 only).
    /// Causes SIGSEGV on RDTSC. Default: `false`.
    pub disable_tsc: bool,
    /// Set `PR_SET_DUMPABLE` to 0 (non-dumpable). Prevents same-UID ptrace
    /// and `/proc/<pid>/mem` access from outside the sandbox. Default: `false`
    /// (i.e. non-dumpable by default).
    pub dumpable: bool,
    /// Forward signals received by the supervisor to the sandboxed child.
    /// When `false`, any signal to the supervisor kills the child with
    /// SIGKILL. Default: `true`.
    pub forward_signals: bool,
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            new_session: true,
            die_with_parent: true,
            no_new_privs: true,
            disable_tsc: false,
            dumpable: false,
            forward_signals: true,
        }
    }
}

/// Source of a seccomp policy.
#[derive(Debug)]
pub enum SeccompSource {
    /// Inline Kafel policy string.
    Inline(String),
    /// Path to a Kafel policy file.
    File(PathBuf),
}

/// A mutable builder for configuring a Linux sandbox.
///
/// Build it directly in Rust, configure the subsystems you need, and then
/// call [`SandboxBuilder::build`] to validate and produce a [`Sandbox`],
/// or [`SandboxBuilder::run`] as a shortcut to build and run.
///
/// ```no_run
/// use pnut::SandboxBuilder;
///
/// let mut sb = SandboxBuilder::new();
/// sb.uid_map(0, 1000, 1)
///   .gid_map(0, 1000, 1)
///   .command("/bin/echo")
///   .arg("hello");
/// let exit_code = sb.run().unwrap();
/// ```
#[derive(Debug)]
pub struct SandboxBuilder {
    mode: RunMode,
    command: Command,
    process: ProcessOptions,
    namespaces: namespace::Config,
    mounts: mount::Table,
    uid_map: Option<IdMap>,
    gid_map: Option<IdMap>,
    env: Option<EnvConfig>,
    rlimits: Option<RlimitsConfig>,
    landlock: Option<LandlockConfig>,
    capabilities: Option<CapsConfig>,
    fd: Option<FdConfig>,
    seccomp: Option<SeccompSource>,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBuilder {
    /// Create a builder with the same defaults as an empty TOML config.
    pub fn new() -> Self {
        Self {
            mode: RunMode::default(),
            command: Command::new(),
            process: ProcessOptions::default(),
            namespaces: namespace::Config::default(),
            mounts: mount::Table::default(),
            uid_map: None,
            gid_map: None,
            env: None,
            rlimits: None,
            landlock: None,
            capabilities: None,
            fd: None,
            seccomp: None,
        }
    }

    /// Replace the command path and clear any existing arguments.
    pub fn command(&mut self, path: impl Into<String>) -> &mut Self {
        self.command.args.clear();
        self.command.args.push(path.into());
        self
    }

    /// Replace the full command vector, including the path.
    pub fn command_with_args<I, S>(&mut self, command: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command.args = command.into_iter().map(Into::into).collect();
        self
    }

    /// Append one argument to the current command vector.
    pub fn arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.command.args.push(arg.into());
        self
    }

    /// Append multiple arguments to the current command vector.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Override `argv[0]` for the executed command.
    pub fn argv0(&mut self, argv0: impl Into<String>) -> &mut Self {
        self.command.argv0 = Some(argv0.into());
        self
    }

    /// Set the working directory inside the sandbox.
    pub fn cwd(&mut self, cwd: impl Into<String>) -> &mut Self {
        self.command.cwd = cwd.into();
        self
    }

    /// Set the sandbox run mode.
    pub fn mode(&mut self, mode: RunMode) -> &mut Self {
        self.mode = mode;
        self
    }

    /// Access the process lifecycle options.
    pub fn process(&mut self) -> &mut ProcessOptions {
        &mut self.process
    }

    /// Set the UID mapping for the user namespace.
    pub fn uid_map(&mut self, inside: u32, outside: u32, count: u32) -> &mut Self {
        self.uid_map = Some(IdMap::new(inside, outside, count));
        self
    }

    /// Set the GID mapping for the user namespace.
    pub fn gid_map(&mut self, inside: u32, outside: u32, count: u32) -> &mut Self {
        self.gid_map = Some(IdMap::new(inside, outside, count));
        self
    }

    /// Access the namespace configuration.
    pub fn namespaces(&mut self) -> &mut crate::namespace::Config {
        &mut self.namespaces
    }

    /// Access the ordered mount table.
    pub fn mounts(&mut self) -> &mut crate::mount::Table {
        &mut self.mounts
    }

    /// Access the environment policy, creating one if needed.
    pub fn env(&mut self) -> &mut crate::env::Config {
        self.env.get_or_insert_with(Default::default)
    }

    /// Access the resource limit configuration, creating one if needed.
    pub fn rlimits(&mut self) -> &mut crate::rlimit::Config {
        self.rlimits.get_or_insert_with(Default::default)
    }

    /// Access the Landlock policy, creating one if needed.
    pub fn landlock(&mut self) -> &mut crate::landlock::Config {
        self.landlock.get_or_insert_with(Default::default)
    }

    /// Access the capability policy, creating one if needed.
    pub fn capabilities(&mut self) -> &mut crate::caps::Config {
        self.capabilities.get_or_insert_with(Default::default)
    }

    /// Access the fd policy, creating one if needed.
    pub fn fd(&mut self) -> &mut crate::fd::Config {
        self.fd.get_or_insert_with(Default::default)
    }

    /// Set the seccomp policy source.
    pub fn seccomp(&mut self, source: SeccompSource) -> &mut Self {
        self.seccomp = Some(source);
        self
    }

    /// Validate configuration and produce a ready-to-run [`Sandbox`].
    pub fn build(self) -> std::result::Result<Sandbox, BuildError> {
        if self.namespaces.hostname.is_some() && !self.namespaces.uts {
            return Err(BuildError::InvalidConfig(
                "hostname is set but UTS namespace is not enabled; set [namespaces] uts = true to use hostname".to_string(),
            ));
        }

        for (i, entry) in self.mounts.iter().enumerate() {
            if entry.dst.is_none() {
                return Err(BuildError::InvalidConfig(format!(
                    "mount entry {i} is missing the required 'dst' field"
                )));
            }

            if entry.bind {
                let Some(src) = entry.src.as_deref() else {
                    return Err(BuildError::InvalidConfig(format!(
                        "mount entry {i}: bind mount requires a 'src' field"
                    )));
                };
                if !Path::new(src).exists() {
                    return Err(BuildError::InvalidConfig(format!(
                        "mount entry {i}: bind mount source path does not exist: {src}"
                    )));
                }
            }

            if !entry.bind && entry.mount_type.is_none() && entry.content.is_none() {
                return Err(BuildError::InvalidConfig(format!(
                    "mount entry {i}: must specify at least one of 'bind', 'type', or 'content'"
                )));
            }
        }

        if let Some(caps_config) = self.capabilities.as_ref() {
            for name in &caps_config.keep {
                name.parse::<caps::Capability>().map_err(|_| {
                    BuildError::InvalidConfig(format!(
                        "invalid capability name '{}'; expected a Linux capability like CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN, etc.",
                        name
                    ))
                })?;
            }
        }

        if let Some(fd_config) = self.fd.as_ref() {
            let mut dst_set = std::collections::HashSet::new();
            for m in &fd_config.mappings {
                if !dst_set.insert(m.dst) {
                    return Err(BuildError::InvalidConfig(format!(
                        "duplicate fd mapping destination: {}",
                        m.dst
                    )));
                }
            }
        }

        let seccomp_program = seccomp::prepare_program(self.seccomp.as_ref(), &self.namespaces)?;

        Ok(Sandbox {
            mode: self.mode,
            command: self.command,
            process: self.process,
            namespaces: self.namespaces,
            mounts: self.mounts,
            uid_map: self.uid_map,
            gid_map: self.gid_map,
            env: self.env,
            rlimits: self.rlimits,
            landlock: self.landlock,
            capabilities: self.capabilities,
            fd: self.fd,
            seccomp_program,
        })
    }

    /// Validate, build, and execute the sandboxed command.
    ///
    /// Convenience method equivalent to `build()?.run()`.
    pub fn run(self) -> Result<i32, Error> {
        if !self.command.has_command() {
            return Err(Error::Other(
                "no command specified. Usage: pnut --config <path> -- <command> [args...]".into(),
            ));
        }
        let sandbox = self.build()?;
        sandbox.run()
    }
}

/// A validated, ready-to-run Linux sandbox.
///
/// Produced by [`SandboxBuilder::build`]. All configuration has been validated
/// and any seccomp policy has been compiled to BPF.
pub struct Sandbox {
    mode: RunMode,
    command: Command,
    process: ProcessOptions,
    pub(crate) namespaces: namespace::Config,
    pub(crate) mounts: mount::Table,
    uid_map: Option<IdMap>,
    gid_map: Option<IdMap>,
    env: Option<EnvConfig>,
    rlimits: Option<RlimitsConfig>,
    landlock: Option<LandlockConfig>,
    capabilities: Option<CapsConfig>,
    fd: Option<FdConfig>,
    seccomp_program: Option<kafel::BpfProgram>,
}

impl Sandbox {
    /// Execute the sandboxed command.
    ///
    /// Returns the propagated exit code from the sandboxed program,
    /// following the same conventions as the `pnut` CLI.
    pub fn run(&self) -> Result<i32, Error> {
        match self.mode {
            RunMode::Execve => run_execve_mode(self),
            RunMode::Once => run_once_mode(self),
        }
    }

    pub(crate) fn working_dir(&self) -> &str {
        &self.command.cwd
    }

    pub(crate) fn mount_table(&self) -> &crate::mount::Table {
        &self.mounts
    }
}

/// STANDALONE_ONCE mode: clone3 a child, supervise it, propagate exit status.
fn run_once_mode(sandbox: &Sandbox) -> Result<i32, Error> {
    let uid_map = sandbox
        .uid_map
        .as_ref()
        .ok_or_else(|| Error::Other("uid_map is required when user namespace is enabled".into()))?;
    let gid_map = sandbox
        .gid_map
        .as_ref()
        .ok_or_else(|| Error::Other("gid_map is required when user namespace is enabled".into()))?;

    // Create sync pipe: parent writes after UID/GID maps are set, child reads to proceed.
    let (sync_read_fd, sync_write_fd) = pipe_pair()?;

    // Block forwarded signals + SIGCHLD before clone3 so that no signals
    // are lost between clone3 and the signalfd loop.
    let mask = supervision_signal_mask();
    mask.thread_block()
        .map_err(|e| Error::Other(format!("failed to block signals: {e}")))?;

    let flags = namespace::clone_flags(&sandbox.namespaces);
    let child = namespace::do_clone3(flags)?;

    let child = match child {
        None => {
            // === CHILD PROCESS ===
            // Unblock signals inherited from parent's signalfd setup.
            let _ = mask.thread_unblock();
            drop(sync_write_fd);
            child_main(sync_read_fd, sandbox);
        }
        Some(cr) => cr,
    };

    // === PARENT PROCESS ===
    let child_pid = child.pid;
    let child_pidfd = child.pidfd;
    drop(sync_read_fd);

    // All parent exit paths must go through cleanup.
    let result = run_parent(
        child_pid,
        &child_pidfd,
        sync_write_fd,
        uid_map,
        gid_map,
        sandbox,
    );

    // Restore signal mask for library callers.
    let _ = mask.thread_unblock();

    result
}

/// Parent-side logic after clone3. Extracted so all error paths are cleaned up
/// by the caller (`run_once_mode`).
fn run_parent(
    child_pid: Pid,
    pidfd: &OwnedFd,
    sync_write_fd: OwnedFd,
    uid_map: &IdMap,
    gid_map: &IdMap,
    sandbox: &Sandbox,
) -> Result<i32, Error> {
    if let Err(e) = idmap::write_id_maps(child_pid, uid_map, gid_map) {
        drop(sync_write_fd);
        let _ = waitpid(child_pid, None);
        return Err(e);
    }

    nix::unistd::write(&sync_write_fd, &[0u8]).map_err(|e| Error::Setup {
        stage: Stage::Clone,
        context: "failed to signal child via sync pipe".into(),
        source: e.into(),
    })?;
    drop(sync_write_fd);

    wait_for_child(child_pid, pidfd, sandbox.process.forward_signals)
}

/// STANDALONE_EXECVE mode: the calling process sets up the sandbox itself and
/// replaces itself with the target command.
fn run_execve_mode(sandbox: &Sandbox) -> Result<i32, Error> {
    let uid_map = sandbox
        .uid_map
        .as_ref()
        .ok_or_else(|| Error::Other("uid_map is required when user namespace is enabled".into()))?;
    let gid_map = sandbox
        .gid_map
        .as_ref()
        .ok_or_else(|| Error::Other("gid_map is required when user namespace is enabled".into()))?;

    let mut flags = namespace::clone_flags(&sandbox.namespaces);
    flags &= !(libc::CLONE_NEWPID as u64);

    let ret = unsafe { libc::unshare(flags as i32) };
    if ret != 0 {
        return Err(Error::Setup {
            stage: Stage::Clone,
            context: "unshare failed".into(),
            source: std::io::Error::last_os_error(),
        });
    }

    let my_pid = nix::unistd::getpid();
    idmap::write_id_maps(my_pid, uid_map, gid_map)?;

    run_child_setup(sandbox);
}

/// Shared child setup sequence used by both execution modes.
fn run_child_setup(sandbox: &Sandbox) -> ! {
    {
        let dumpable = if sandbox.process.dumpable { 1 } else { 0 };
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, dumpable, 0, 0, 0) };
        if ret != 0 {
            eprintln!(
                "pnut: failed to set PR_SET_DUMPABLE: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(126);
        }
    }

    if sandbox.namespaces.mount
        && !sandbox.mounts.is_empty()
        && let Err(e) = mount::setup_filesystem(sandbox)
    {
        eprintln!("pnut: filesystem setup failed: {e}");
        std::process::exit(126);
    }

    if let Some(ref hostname) = sandbox.namespaces.hostname
        && sandbox.namespaces.uts
        && let Err(e) = nix::unistd::sethostname(hostname)
    {
        eprintln!("pnut: failed to set hostname to '{hostname}': {e}");
        std::process::exit(126);
    }

    if sandbox.namespaces.net
        && let Err(e) = net::bring_up_loopback()
    {
        eprintln!("pnut: loopback setup failed: {e}");
        std::process::exit(126);
    }

    if let Some(ref rlimits_config) = sandbox.rlimits
        && let Err(e) = rlimit::apply_rlimits(rlimits_config)
    {
        eprintln!("pnut: rlimits setup failed: {e}");
        std::process::exit(126);
    }

    if let Some(ref landlock_config) = sandbox.landlock
        && let Err(e) = landlock::apply_landlock(landlock_config)
    {
        eprintln!("pnut: landlock setup failed: {e}");
        std::process::exit(126);
    }

    if let Some(ref env_config) = sandbox.env {
        env::setup_environment(env_config);
    }

    if let Some(ref caps_config) = sandbox.capabilities
        && let Err(e) = capmod::apply_capabilities(caps_config)
    {
        eprintln!("pnut: capability setup failed: {e}");
        std::process::exit(126);
    }

    if sandbox.process.new_session
        && let Err(e) = nix::unistd::setsid()
    {
        eprintln!("pnut: setsid failed: {e}");
        std::process::exit(126);
    }

    {
        let fd_config = sandbox.fd.as_ref();
        let default_config = fd::Config::default();
        let config = fd_config.unwrap_or(&default_config);
        if let Err(e) = fd::apply_fd_config(config) {
            eprintln!("pnut: fd setup failed: {e}");
            std::process::exit(126);
        }
    }

    if sandbox.process.disable_tsc {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Err(e) = disable_tsc() {
            eprintln!("pnut: failed to disable TSC: {e}");
            std::process::exit(126);
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            eprintln!("pnut: disable_tsc is only supported on x86/x86_64");
            std::process::exit(126);
        }
    }

    if sandbox.process.no_new_privs {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            eprintln!(
                "pnut: failed to set PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(126);
        }
    }

    if let Some(program) = sandbox.seccomp_program.as_ref()
        && let Err(e) = kafel::install_filter(program)
    {
        eprintln!("pnut: seccomp filter installation failed: {e}");
        std::process::exit(126);
    }

    do_exec(sandbox);
}

/// Child process entry point for `once` mode.
fn child_main(sync_read_fd: OwnedFd, sandbox: &Sandbox) -> ! {
    if sandbox.process.die_with_parent {
        if let Err(e) = prctl::set_pdeathsig(Signal::SIGKILL) {
            eprintln!("pnut: failed to set PR_SET_PDEATHSIG: {e}");
            std::process::exit(126);
        }

        if nix::unistd::getppid() == Pid::from_raw(1) {
            std::process::exit(126);
        }
    }

    {
        let file = std::fs::File::from(sync_read_fd);
        let mut pipe = std::io::BufReader::new(file);

        let mut buf = [0u8; 1];
        match pipe.read_exact(&mut buf) {
            Ok(()) => {}
            Err(_) => {
                eprintln!("pnut: parent failed during setup");
                std::process::exit(126);
            }
        }
    }

    run_child_setup(sandbox);
}

/// Build argv and `execv` the target command.
fn do_exec(sandbox: &Sandbox) -> ! {
    let command = &sandbox.command.args;
    let path = CString::new(command[0].as_str()).unwrap_or_else(|_| {
        eprintln!("pnut: command path contains null byte");
        std::process::exit(126);
    });

    let mut args: Vec<CString> = command
        .iter()
        .map(|a| {
            CString::new(a.as_str()).unwrap_or_else(|_| {
                eprintln!("pnut: argument contains null byte");
                std::process::exit(126);
            })
        })
        .collect();

    if let Some(ref argv0) = sandbox.command.argv0 {
        args[0] = CString::new(argv0.as_str()).unwrap_or_else(|_| {
            eprintln!("pnut: argv0 contains null byte");
            std::process::exit(126);
        });
    }

    let err = nix::unistd::execv(&path, &args);
    match err {
        Err(nix::errno::Errno::ENOENT) => {
            eprintln!("pnut: command not found: {}", command[0]);
            std::process::exit(127);
        }
        Err(nix::errno::Errno::EACCES) => {
            eprintln!("pnut: permission denied: {}", command[0]);
            std::process::exit(126);
        }
        Err(e) => {
            eprintln!("pnut: exec failed: {e}");
            std::process::exit(126);
        }
        Ok(_) => unreachable!(),
    }
}

/// Signals forwarded to the sandboxed child (or that trigger SIGKILL when
/// `forward_signals` is false).
const FORWARDED_SIGNALS: &[Signal] = &[
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
];

/// Build the signal mask used by both `run_once_mode` (to block before clone3)
/// and `wait_for_child` (to create the signalfd).
fn supervision_signal_mask() -> SigSet {
    let mut mask = SigSet::empty();
    for &sig in FORWARDED_SIGNALS {
        mask.add(sig);
    }
    mask.add(Signal::SIGCHLD);
    mask
}

fn wait_for_child(child_pid: Pid, pidfd: &OwnedFd, forward_signals: bool) -> Result<i32, Error> {
    // Signals are already blocked before clone3. Create signalfd to receive them.
    // We detect child exit via the pidfd (becomes readable), not SIGCHLD —
    // this avoids SIGCHLD races in multi-threaded processes.
    let mask = supervision_signal_mask();
    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .map_err(|e| Error::Other(format!("signalfd creation failed: {e}")))?;

    // Poll on both:
    // - pidfd: becomes readable when child exits (race-free, no SIGCHLD needed)
    // - signalfd: delivers forwarded signals (SIGTERM, SIGINT, etc.)
    loop {
        let mut fds = [
            PollFd::new(pidfd.as_fd(), PollFlags::POLLIN),
            PollFd::new(sfd.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Other(format!("poll failed: {e}"))),
        }

        // Check pidfd — child exited.
        if fds[0]
            .revents()
            .is_some_and(|r: PollFlags| r.contains(PollFlags::POLLIN))
        {
            match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => return Ok(128 + signal as i32),
                _ => continue,
            }
        }

        // Drain signalfd — forward or kill.
        while let Ok(Some(siginfo)) = sfd.read_signal() {
            if siginfo.ssi_signo == libc::SIGCHLD as u32 {
                continue;
            }
            if forward_signals {
                pidfd_send_signal(pidfd, siginfo.ssi_signo as i32);
            } else {
                pidfd_send_signal(pidfd, libc::SIGKILL);
            }
        }
    }
}

/// Send a signal to a process via its pidfd. Race-free: the signal is
/// always delivered to the intended process even if its PID has been recycled.
/// ESRCH (child already exited) is silently ignored; other errors are logged.
fn pidfd_send_signal(pidfd: &OwnedFd, sig: i32) {
    use std::os::fd::AsRawFd;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd() as libc::c_long,
            sig as libc::c_long,
            std::ptr::null::<libc::siginfo_t>() as libc::c_long,
            0 as libc::c_long,
        )
    };
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            eprintln!("pnut: pidfd_send_signal({sig}) failed: {err}");
        }
    }
}

fn pipe_pair() -> Result<(OwnedFd, OwnedFd), Error> {
    let (read_fd, write_fd) = nix::unistd::pipe().map_err(|e| Error::Setup {
        stage: Stage::Clone,
        context: "pipe() failed".into(),
        source: e.into(),
    })?;
    Ok((read_fd, write_fd))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn disable_tsc() -> std::result::Result<(), Error> {
    // PR_SET_TSC = 26, PR_TSC_SIGSEGV = 2
    let ret = unsafe { libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV) };
    if ret != 0 {
        return Err(Error::Setup {
            stage: Stage::Clone,
            context: "prctl(PR_SET_TSC, PR_TSC_SIGSEGV) failed".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::SandboxBuilder;

    #[test]
    fn landlock_config_accumulates_paths() {
        let mut builder = SandboxBuilder::new();
        builder
            .landlock()
            .allow_read("/usr")
            .allow_write("/tmp")
            .allow_execute("/usr/bin");

        let landlock = builder.landlock.as_ref().unwrap();
        assert_eq!(landlock.allowed_read, vec!["/usr"]);
        assert_eq!(landlock.allowed_write, vec!["/tmp"]);
        assert_eq!(landlock.allowed_execute, vec!["/usr/bin"]);
    }

    #[test]
    fn command_builder_replaces_then_appends_args() {
        let mut builder = SandboxBuilder::new();
        builder.command("/bin/echo").arg("hello").arg("world");
        assert_eq!(builder.command.args, vec!["/bin/echo", "hello", "world"]);

        builder.command_with_args(["/bin/true"]);
        assert_eq!(builder.command.args, vec!["/bin/true"]);
    }

    #[test]
    fn seccomp_source_inline_round_trips() {
        let mut builder = SandboxBuilder::new();
        builder.seccomp(super::SeccompSource::Inline(
            "USE allow_default_policy DEFAULT KILL".to_string(),
        ));

        assert!(matches!(
            builder.seccomp,
            Some(super::SeccompSource::Inline(ref s)) if s == "USE allow_default_policy DEFAULT KILL"
        ));
    }
}
