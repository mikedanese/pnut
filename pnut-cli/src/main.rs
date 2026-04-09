use anyhow::{Context, Result};
use clap::Parser;
use pnut::{BuildError, RunMode, SandboxBuilder, SeccompSource};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// pnut — a lightweight, unprivileged Linux sandbox.
///
/// Confines processes using user namespaces, mount isolation, and pivot_root.
/// Runs entirely without root, setuid, or special capabilities.
#[derive(Parser, Debug)]
#[command(name = "pnut", version, about, long_about = None)]
struct Cli {
    /// Path to the TOML sandbox configuration file
    #[arg(short, long)]
    config: PathBuf,

    /// Command and arguments to run inside the sandbox.
    /// Specify after '--' separator.
    #[arg(trailing_var_arg = true, required = false)]
    command: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxConfig {
    #[serde(default)]
    sandbox: SettingsConfig,
    #[serde(default)]
    namespaces: NamespaceConfig,
    #[serde(default)]
    mount: Vec<MountEntryConfig>,
    #[serde(default)]
    uid_map: Option<IdMapConfig>,
    #[serde(default)]
    gid_map: Option<IdMapConfig>,
    #[serde(default)]
    env: Option<EnvConfig>,
    #[serde(default)]
    rlimits: Option<RlimitsConfig>,
    #[serde(default)]
    landlock: Option<LandlockConfig>,
    #[serde(default)]
    capabilities: Option<CapabilitiesConfig>,
    #[serde(default)]
    seccomp_policy: Option<String>,
    #[serde(default)]
    seccomp_policy_file: Option<String>,
    #[serde(rename = "seccomp", default)]
    legacy_seccomp: Option<toml::Value>,
    #[serde(default)]
    fd: Option<FdPolicyConfig>,
    #[serde(default)]
    run: Option<RunConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsConfig {
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default = "default_cwd")]
    cwd: String,
    #[serde(default)]
    mode: RunModeConfig,
    #[serde(default = "default_true")]
    new_session: bool,
    #[serde(default = "default_true")]
    die_with_parent: bool,
    #[serde(default = "default_true")]
    no_new_privs: bool,
    #[serde(default)]
    argv0: Option<String>,
    #[serde(default)]
    disable_tsc: bool,
    #[serde(default)]
    dumpable: bool,
    #[serde(default = "default_true")]
    forward_signals: bool,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            hostname: None,
            cwd: default_cwd(),
            mode: RunModeConfig::default(),
            new_session: true,
            die_with_parent: true,
            no_new_privs: true,
            argv0: None,
            disable_tsc: false,
            dumpable: false,
            forward_signals: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RunModeConfig {
    #[default]
    Once,
    Execve,
}

impl From<RunModeConfig> for RunMode {
    fn from(mode: RunModeConfig) -> Self {
        match mode {
            RunModeConfig::Once => RunMode::Once,
            RunModeConfig::Execve => RunMode::Execve,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceConfig {
    #[serde(default = "default_true")]
    user: bool,
    #[serde(default = "default_true")]
    pid: bool,
    #[serde(default = "default_true")]
    mount: bool,
    #[serde(default = "default_true")]
    uts: bool,
    #[serde(default = "default_true")]
    ipc: bool,
    #[serde(default = "default_true")]
    net: bool,
    #[serde(default = "default_true")]
    cgroup: bool,
    #[serde(default)]
    time: bool,
    #[serde(default)]
    allow_nested_userns: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            user: true,
            pid: true,
            mount: true,
            uts: true,
            ipc: true,
            net: true,
            cgroup: true,
            time: false,
            allow_nested_userns: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProcSubsetConfig {
    Pid,
}

impl From<ProcSubsetConfig> for pnut::mount::ProcSubset {
    fn from(c: ProcSubsetConfig) -> Self {
        match c {
            ProcSubsetConfig::Pid => Self::Pid,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum HidePidConfig {
    #[serde(alias = "0")]
    Visible,
    #[serde(alias = "1")]
    Hidden,
    #[serde(alias = "2")]
    Invisible,
}

impl From<HidePidConfig> for pnut::mount::HidePid {
    fn from(c: HidePidConfig) -> Self {
        match c {
            HidePidConfig::Visible => Self::Visible,
            HidePidConfig::Hidden => Self::Hidden,
            HidePidConfig::Invisible => Self::Invisible,
        }
    }
}

fn default_proc_subset() -> Option<ProcSubsetConfig> {
    Some(ProcSubsetConfig::Pid)
}

fn default_hidepid() -> Option<HidePidConfig> {
    Some(HidePidConfig::Invisible)
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum MountEntryConfig {
    Bind {
        src: String,
        dst: String,
        #[serde(default = "default_true")]
        read_only: bool,
    },
    Tmpfs {
        dst: String,
        #[serde(default)]
        size: Option<u64>,
        #[serde(default)]
        perms: Option<String>,
    },
    Proc {
        dst: String,
        #[serde(default = "default_proc_subset")]
        proc_subset: Option<ProcSubsetConfig>,
        #[serde(default = "default_hidepid")]
        hidepid: Option<HidePidConfig>,
    },
    Mqueue {
        dst: String,
    },
    File {
        dst: String,
        content: String,
        #[serde(default = "default_true")]
        read_only: bool,
    },
}

impl From<MountEntryConfig> for pnut::mount::Entry {
    fn from(config: MountEntryConfig) -> Self {
        match config {
            MountEntryConfig::Bind {
                src,
                dst,
                read_only,
            } => Self {
                src: Some(src),
                dst: Some(dst),
                bind: true,
                read_only,
                mount_type: None,
                content: None,
                size: None,
                perms: None,
                proc_subset: None,
                hidepid: None,
            },
            MountEntryConfig::Tmpfs { dst, size, perms } => Self {
                src: None,
                dst: Some(dst),
                bind: false,
                read_only: false,
                mount_type: Some("tmpfs".to_string()),
                content: None,
                size,
                perms,
                proc_subset: None,
                hidepid: None,
            },
            MountEntryConfig::Proc {
                dst,
                proc_subset,
                hidepid,
            } => Self {
                src: None,
                dst: Some(dst),
                bind: false,
                read_only: false,
                mount_type: Some("proc".to_string()),
                content: None,
                size: None,
                perms: None,
                proc_subset: proc_subset.map(Into::into),
                hidepid: hidepid.map(Into::into),
            },
            MountEntryConfig::Mqueue { dst } => Self {
                src: None,
                dst: Some(dst),
                bind: false,
                read_only: false,
                mount_type: Some("mqueue".to_string()),
                content: None,
                size: None,
                perms: None,
                proc_subset: None,
                hidepid: None,
            },
            MountEntryConfig::File {
                dst,
                content,
                read_only,
            } => Self {
                src: None,
                dst: Some(dst),
                bind: false,
                read_only,
                mount_type: None,
                content: Some(content),
                size: None,
                perms: None,
                proc_subset: None,
                hidepid: None,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdMapConfig {
    #[serde(default)]
    inside: u32,
    outside: u32,
    #[serde(default = "default_count")]
    count: u32,
}

impl From<IdMapConfig> for pnut::idmap::Map {
    fn from(config: IdMapConfig) -> Self {
        Self::new(config.inside, config.outside, config.count)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvConfig {
    #[serde(default)]
    clear: bool,
    #[serde(default)]
    set: HashMap<String, String>,
    #[serde(default)]
    keep: Vec<String>,
}

impl From<EnvConfig> for pnut::env::Config {
    fn from(config: EnvConfig) -> Self {
        Self {
            clear: config.clear,
            set: config.set,
            keep: config.keep,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RlimitsConfig {
    #[serde(default)]
    nofile: Option<u64>,
    #[serde(default)]
    nproc: Option<u64>,
    #[serde(default)]
    fsize_mb: Option<u64>,
    #[serde(default)]
    stack_mb: Option<u64>,
    #[serde(default)]
    as_mb: Option<u64>,
    #[serde(default)]
    core_mb: Option<u64>,
    #[serde(default)]
    cpu: Option<u64>,
}

impl From<RlimitsConfig> for pnut::rlimit::Config {
    fn from(config: RlimitsConfig) -> Self {
        Self {
            nofile: config.nofile,
            nproc: config.nproc,
            fsize_mb: config.fsize_mb,
            stack_mb: config.stack_mb,
            as_mb: config.as_mb,
            core_mb: config.core_mb,
            cpu: config.cpu,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LandlockConfig {
    #[serde(default)]
    allowed_read: Vec<String>,
    #[serde(default)]
    allowed_write: Vec<String>,
    #[serde(default)]
    allowed_execute: Vec<String>,
    /// Paths allowed for cross-directory rename/link (Landlock ABI V2+).
    #[serde(default)]
    allowed_refer: Vec<String>,
    /// Paths where file truncation is allowed (Landlock ABI V3+).
    #[serde(default)]
    allowed_truncate: Vec<String>,
    /// TCP ports the sandboxed process may bind (Landlock ABI V4+).
    #[serde(default)]
    allowed_bind: Vec<u16>,
    /// TCP ports the sandboxed process may connect to (Landlock ABI V4+).
    #[serde(default)]
    allowed_connect: Vec<u16>,
    /// Paths where device ioctl commands are allowed (Landlock ABI V5+).
    #[serde(default)]
    allowed_ioctl_dev: Vec<String>,
}

impl From<LandlockConfig> for pnut::landlock::Config {
    fn from(config: LandlockConfig) -> Self {
        Self {
            allowed_read: config.allowed_read,
            allowed_write: config.allowed_write,
            allowed_execute: config.allowed_execute,
            allowed_refer: config.allowed_refer,
            allowed_truncate: config.allowed_truncate,
            allowed_bind: config.allowed_bind,
            allowed_connect: config.allowed_connect,
            allowed_ioctl_dev: config.allowed_ioctl_dev,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesConfig {
    #[serde(default)]
    keep: Vec<String>,
}

impl CapabilitiesConfig {
    fn into_config(self) -> Result<pnut::caps::Config> {
        let mut keep = Vec::with_capacity(self.keep.len());
        for name in &self.keep {
            let cap = name.parse::<pnut::caps::Capability>().map_err(|_| {
                BuildError::InvalidConfig(format!(
                    "invalid capability name '{name}'; expected CAP_NET_BIND_SERVICE, CAP_SYS_ADMIN, etc."
                ))
            })?;
            keep.push(cap);
        }
        Ok(pnut::caps::Config { keep })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FdPolicyConfig {
    #[serde(default = "default_true")]
    close_fds: bool,
    #[serde(default)]
    map: Vec<FdMappingConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FdMappingConfig {
    src: i32,
    dst: i32,
}

impl From<FdPolicyConfig> for pnut::fd::Config {
    fn from(config: FdPolicyConfig) -> Self {
        Self {
            close_fds: config.close_fds,
            mappings: config
                .map
                .into_iter()
                .map(|m| pnut::fd::FdMapping {
                    src: m.src,
                    dst: m.dst,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConfig {
    path: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    argv0: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_cwd() -> String {
    "/".to_string()
}

fn default_count() -> u32 {
    1
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            // Config validation errors exit 126 ("command cannot execute"),
            // matching the child-side behavior for sandbox setup failures.
            let is_build_error = e.is::<BuildError>()
                || e.downcast_ref::<pnut::Error>()
                    .is_some_and(|e| matches!(e, pnut::Error::Build(_)));
            if is_build_error {
                eprintln!("pnut: {e:#}");
                ExitCode::from(126)
            } else {
                eprintln!("pnut: {e:#}");
                ExitCode::from(1)
            }
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    let mut builder = load_sandbox(&cli.config)?;

    // Resolve the command: CLI args take priority, then [run] section in config.
    if !cli.command.is_empty() {
        builder.command_with_args(cli.command);
    }

    Ok(builder.run()?)
}

fn load_sandbox(path: &Path) -> Result<SandboxBuilder> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let config: SandboxConfig = toml::from_str(&contents).map_err(|e| {
        BuildError::InvalidConfig(format!("failed to parse config {}: {e}", path.display()))
    })?;
    sandbox_from_config(config)
}

fn sandbox_from_config(config: SandboxConfig) -> Result<SandboxBuilder> {
    let SandboxConfig {
        sandbox: settings,
        namespaces,
        mount,
        uid_map,
        gid_map,
        env,
        rlimits,
        landlock,
        capabilities,
        fd,
        seccomp_policy,
        seccomp_policy_file,
        legacy_seccomp,
        run,
    } = config;

    if legacy_seccomp.is_some() {
        return Err(BuildError::InvalidConfig(
            "legacy [seccomp] config is no longer supported; use top-level seccomp_policy or seccomp_policy_file".to_string()
        )
        .into());
    }

    let mut builder = SandboxBuilder::new();

    // Dissolve SettingsConfig into appropriate targets.
    builder.mode(settings.mode.into());
    builder.cwd(settings.cwd);
    if let Some(argv0) = settings.argv0 {
        builder.argv0(argv0);
    }
    builder.process().new_session = settings.new_session;
    builder.process().die_with_parent = settings.die_with_parent;
    builder.process().no_new_privs = settings.no_new_privs;
    builder.process().disable_tsc = settings.disable_tsc;
    builder.process().dumpable = settings.dumpable;
    builder.process().forward_signals = settings.forward_signals;

    // Namespace config + hostname from settings.
    let ns_config = pnut::namespace::Config {
        user: namespaces.user,
        pid: namespaces.pid,
        mount: namespaces.mount,
        uts: namespaces.uts,
        ipc: namespaces.ipc,
        net: namespaces.net,
        cgroup: namespaces.cgroup,
        time: namespaces.time,
        hostname: settings.hostname,
        allow_nested_userns: namespaces.allow_nested_userns,
    };
    *builder.namespaces() = ns_config;

    builder.mounts().extend(mount.into_iter().map(Into::into));

    if let Some(map) = uid_map {
        let map: pnut::idmap::Map = map.into();
        builder.uid_map(map.inside, map.outside, map.count);
    }
    if let Some(map) = gid_map {
        let map: pnut::idmap::Map = map.into();
        builder.gid_map(map.inside, map.outside, map.count);
    }
    if let Some(config) = env {
        *builder.env() = config.into();
    }
    if let Some(config) = rlimits {
        *builder.rlimits() = config.into();
    }
    if let Some(config) = landlock {
        *builder.landlock() = config.into();
    }
    if let Some(config) = capabilities {
        *builder.capabilities() = config.into_config()?;
    }
    if let Some(config) = fd {
        *builder.fd() = config.into();
    }
    match (seccomp_policy, seccomp_policy_file) {
        (Some(_), Some(_)) => {
            return Err(BuildError::InvalidConfig(
                "seccomp_policy and seccomp_policy_file are mutually exclusive; configure only one"
                    .to_string(),
            )
            .into());
        }
        (Some(policy), None) => {
            builder.seccomp(SeccompSource::Inline(policy));
        }
        (None, Some(path)) => {
            builder.seccomp(SeccompSource::File(path.into()));
        }
        (None, None) => {}
    }
    if let Some(run) = run {
        let RunConfig { path, args, argv0 } = run;
        if let Some(argv0) = argv0 {
            builder.argv0(argv0);
        }
        let mut command = vec![path];
        command.extend(args);
        builder.command_with_args(command);
    }

    Ok(builder)
}
