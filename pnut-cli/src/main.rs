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
    #[serde(default)]
    uts: bool,
    #[serde(default)]
    ipc: bool,
    #[serde(default)]
    net: bool,
    #[serde(default)]
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
            uts: false,
            ipc: false,
            net: false,
            cgroup: false,
            time: false,
            allow_nested_userns: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountEntryConfig {
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    dst: Option<String>,
    #[serde(default)]
    bind: bool,
    #[serde(default)]
    read_only: bool,
    #[serde(rename = "type", default)]
    mount_type: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    perms: Option<String>,
    #[serde(default = "default_proc_subset")]
    proc_subset: Option<String>,
    #[serde(default = "default_hidepid")]
    hidepid: Option<String>,
}

fn default_proc_subset() -> Option<String> {
    Some("pid".to_string())
}

fn default_hidepid() -> Option<String> {
    Some("invisible".to_string())
}

impl From<MountEntryConfig> for pnut::mount::Entry {
    fn from(config: MountEntryConfig) -> Self {
        let proc_subset = config.proc_subset.as_deref().map(|s| match s {
            "pid" => pnut::mount::ProcSubset::Pid,
            other => panic!("unknown proc_subset value: {other}"),
        });
        let hidepid = config.hidepid.as_deref().map(|s| match s {
            "invisible" | "2" => pnut::mount::HidePid::Invisible,
            "hidden" | "1" => pnut::mount::HidePid::Hidden,
            "visible" | "0" => pnut::mount::HidePid::Visible,
            other => panic!("unknown hidepid value: {other}"),
        });
        Self {
            src: config.src,
            dst: config.dst,
            bind: config.bind,
            read_only: config.read_only,
            mount_type: config.mount_type,
            content: config.content,
            size: config.size,
            perms: config.perms,
            proc_subset,
            hidepid,
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
}

impl From<LandlockConfig> for pnut::landlock::Config {
    fn from(config: LandlockConfig) -> Self {
        Self {
            allowed_read: config.allowed_read,
            allowed_write: config.allowed_write,
            allowed_execute: config.allowed_execute,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitiesConfig {
    #[serde(default)]
    keep: Vec<String>,
}

impl From<CapabilitiesConfig> for pnut::caps::Config {
    fn from(config: CapabilitiesConfig) -> Self {
        Self { keep: config.keep }
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
        *builder.capabilities() = config.into();
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
