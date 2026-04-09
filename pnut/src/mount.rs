//! Filesystem staging, mount setup, and pivot-root support.

mod dev;
mod syscall;

use crate::error::{Error, Stage};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::pivot_root;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::slice;

use crate::Sandbox;

/// Proc mount `subset=` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcSubset {
    /// `subset=pid` — only PID-related entries are visible.
    /// Hides `/proc/sys`, `/proc/kallsyms`, `/proc/modules`, etc.
    Pid,
}

/// Proc mount `hidepid=` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidePid {
    /// `hidepid=0` — all `/proc/<pid>` directories are visible to everyone.
    Visible,
    /// `hidepid=1` — users cannot access other users' `/proc/<pid>` contents.
    Hidden,
    /// `hidepid=2` / `hidepid=invisible` — other users' `/proc/<pid>` directories
    /// are completely invisible.
    Invisible,
}

/// One filesystem mount operation.
#[derive(Debug, Clone)]
pub struct Entry {
    pub src: Option<String>,
    pub dst: Option<String>,
    pub bind: bool,
    pub read_only: bool,
    pub mount_type: Option<String>,
    pub content: Option<String>,
    pub size: Option<u64>,
    pub perms: Option<String>,
    /// Proc mount: `subset=` option. Default: `Some(ProcSubset::Pid)`.
    /// Set to `None` to mount full proc.
    pub proc_subset: Option<ProcSubset>,
    /// Proc mount: `hidepid=` option. Default: `Some(HidePid::Invisible)`.
    /// Set to `None` to use kernel default (`hidepid=0`).
    pub hidepid: Option<HidePid>,
}

/// Ordered filesystem mount operations for a sandbox.
#[derive(Debug, Default)]
pub struct Table {
    entries: Vec<Entry>,
}

impl Table {
    /// Create an empty mount table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one mount entry.
    pub fn push(&mut self, entry: Entry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Append many mount entries.
    pub fn extend<I>(&mut self, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = Entry>,
    {
        self.entries.extend(entries);
        self
    }

    /// Add a recursive bind mount.
    pub fn bind(&mut self, src: impl Into<String>, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: Some(src.into()),
            dst: Some(dst.into()),
            bind: true,
            read_only: false,
            mount_type: None,
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a read-only recursive bind mount.
    pub fn bind_read_only(&mut self, src: impl Into<String>, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: Some(src.into()),
            dst: Some(dst.into()),
            bind: true,
            read_only: true,
            mount_type: None,
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a tmpfs mount at the destination path.
    pub fn tmpfs(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("tmpfs".to_string()),
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a tmpfs mount with explicit size and permissions.
    pub fn tmpfs_with_options<P>(
        &mut self,
        dst: impl Into<String>,
        size: Option<u64>,
        perms: Option<P>,
    ) -> &mut Self
    where
        P: Into<String>,
    {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("tmpfs".to_string()),
            content: None,
            size,
            perms: perms.map(Into::into),
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a procfs mount at the destination path with default hardening
    /// (`subset=pid`, `hidepid=invisible`).
    pub fn proc(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("proc".to_string()),
            content: None,
            size: None,
            perms: None,
            proc_subset: Some(ProcSubset::Pid),
            hidepid: Some(HidePid::Invisible),
        })
    }

    /// Add an mqueue mount at the destination path.
    pub fn mqueue(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("mqueue".to_string()),
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Inject a file into the sandbox filesystem.
    pub fn inject_file(&mut self, dst: impl Into<String>, content: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: None,
            content: Some(content.into()),
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Inject a read-only file into the sandbox filesystem.
    pub fn inject_read_only_file(
        &mut self,
        dst: impl Into<String>,
        content: impl Into<String>,
    ) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: true,
            mount_type: None,
            content: Some(content.into()),
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Iterate over mount entries in insertion order.
    pub fn iter(&self) -> slice::Iter<'_, Entry> {
        self.entries.iter()
    }

    /// Return whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'a> IntoIterator for &'a Table {
    type Item = &'a Entry;
    type IntoIter = slice::Iter<'a, Entry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

const PUT_OLD: &str = ".old_root";
const CONTENT_STAGING: &str = ".pnut-content";

fn mnt(context: impl Into<String>, source: impl Into<std::io::Error>) -> Error {
    Error::Setup {
        stage: Stage::Mount,
        context: context.into(),
        source: source.into(),
    }
}

fn mnt_nix(context: impl Into<String>, e: nix::errno::Errno) -> Error {
    Error::Setup {
        stage: Stage::Mount,
        context: context.into(),
        source: e.into(),
    }
}

/// Set up the isolated filesystem and pivot_root into it.
///
/// Called in the child process after fork.
pub(crate) fn setup_filesystem(sandbox: &Sandbox) -> Result<(), Error> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| mnt_nix("failed to make mount tree recursively private", e))?;

    let new_root = PathBuf::from("/tmp/pnut-newroot");
    fs::create_dir_all(&new_root).map_err(|e| mnt("failed to create new root directory", e))?;

    mount(
        Some("tmpfs"),
        &new_root,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| mnt_nix("failed to mount tmpfs as new root", e))?;

    let put_old = new_root.join(PUT_OLD);
    fs::create_dir_all(&put_old).map_err(|e| mnt("failed to create put_old directory", e))?;

    let staging = new_root.join(CONTENT_STAGING);
    fs::create_dir_all(&staging)
        .map_err(|e| mnt("failed to create content staging directory", e))?;

    let mut content_idx: usize = 0;
    for (i, entry) in sandbox.mount_table().iter().enumerate() {
        process_mount_entry(entry, &new_root, &staging, &mut content_idx)
            .map_err(|e| Error::Other(format!("failed to process mount entry {i}: {e}")))?;
    }

    dev::setup_dev(&new_root)?;

    pivot_root(&new_root, &put_old).map_err(|e| Error::Setup {
        stage: Stage::Pivot,
        context: "pivot_root failed".into(),
        source: e.into(),
    })?;

    let old_root_inside = PathBuf::from("/").join(PUT_OLD);
    umount2(&old_root_inside, MntFlags::MNT_DETACH)
        .map_err(|e| mnt_nix("failed to unmount old root", e))?;
    let _ = fs::remove_dir(&old_root_inside);

    let staging_inside = PathBuf::from("/").join(CONTENT_STAGING);
    let _ = fs::remove_dir_all(&staging_inside);

    let cwd = sandbox.working_dir();
    std::env::set_current_dir(cwd).map_err(|e| mnt(format!("failed to chdir to {cwd}"), e))?;

    Ok(())
}

fn process_mount_entry(
    entry: &Entry,
    new_root: &Path,
    staging: &Path,
    content_idx: &mut usize,
) -> Result<(), Error> {
    if let Some(ref content) = entry.content {
        return process_content_entry(entry, content, new_root, staging, content_idx);
    }

    if entry.bind {
        return process_bind_mount(entry, new_root);
    }

    if let Some(ref mount_type) = entry.mount_type {
        return match mount_type.as_str() {
            "tmpfs" => process_tmpfs_mount(entry, new_root),
            "proc" => process_proc_mount(entry, new_root),
            "mqueue" => process_mqueue_mount(entry, new_root),
            other => Err(Error::Other(format!("unsupported mount type: {other}"))),
        };
    }

    Err(Error::Other(
        "mount entry has no bind, type, or content field".into(),
    ))
}

fn process_bind_mount(entry: &Entry, new_root: &Path) -> Result<(), Error> {
    let src = entry
        .src
        .as_deref()
        .ok_or_else(|| Error::Other("bind mount requires a src field".into()))?;
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("bind mount requires a dst field".into()))?;

    let target = new_root.join(dst.trim_start_matches('/'));
    ensure_mount_point(&target, src)?;

    mount(
        Some(src),
        &target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| mnt_nix(format!("bind mount {src} -> {dst} failed"), e))?;

    if entry.read_only {
        mount(
            None::<&str>,
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| mnt_nix(format!("read-only remount of {dst} failed"), e))?;
    }

    Ok(())
}

fn process_tmpfs_mount(entry: &Entry, new_root: &Path) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("tmpfs mount requires a dst field".into()))?;

    let target = new_root.join(dst.trim_start_matches('/'));
    fs::create_dir_all(&target)
        .map_err(|e| mnt(format!("failed to create directory for tmpfs at {dst}"), e))?;

    let mut data = MountData::new();
    if let Some(size) = entry.size {
        data.push("size", &size.to_string())?;
    }
    if let Some(ref perms) = entry.perms {
        let mode = u32::from_str_radix(perms.trim_start_matches('0'), 8)
            .map_err(|e| Error::Other(format!("invalid permissions: {perms}: {e}")))?;
        data.push("mode", &format!("{mode:04o}"))?;
    }
    let data = data.to_string();

    mount(
        Some("tmpfs"),
        &target,
        Some("tmpfs"),
        MsFlags::empty(),
        data.as_deref(),
    )
    .map_err(|e| mnt_nix(format!("tmpfs mount at {dst} failed"), e))?;

    Ok(())
}

/// Builder for mount data strings (the `data` argument to `mount(2)`).
///
/// Collects key=value pairs and joins them with commas.
/// Returns `None` when empty. Rejects duplicate keys.
struct MountData {
    parts: Vec<String>,
    keys: HashSet<String>,
}

impl MountData {
    fn new() -> Self {
        Self {
            parts: Vec::new(),
            keys: HashSet::new(),
        }
    }

    fn push(&mut self, key: &str, value: &str) -> Result<(), Error> {
        if !self.keys.insert(key.to_string()) {
            return Err(Error::Other(format!("duplicate mount data key: {key}")));
        }
        self.parts.push(format!("{key}={value}"));
        Ok(())
    }

    fn to_string(&self) -> Option<String> {
        if self.parts.is_empty() {
            None
        } else {
            Some(self.parts.join(","))
        }
    }
}

fn process_proc_mount(entry: &Entry, new_root: &Path) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("proc mount requires a dst field".into()))?;

    let target = new_root.join(dst.trim_start_matches('/'));
    fs::create_dir_all(&target)
        .map_err(|e| mnt(format!("failed to create directory for proc at {dst}"), e))?;

    let mut data = MountData::new();
    if let Some(subset) = &entry.proc_subset {
        data.push(
            "subset",
            match subset {
                ProcSubset::Pid => "pid",
            },
        )?;
    }
    if let Some(hidepid) = &entry.hidepid {
        data.push(
            "hidepid",
            match hidepid {
                HidePid::Visible => "0",
                HidePid::Hidden => "1",
                HidePid::Invisible => "invisible",
            },
        )?;
    }
    let data = data.to_string();

    mount(
        Some("proc"),
        &target,
        Some("proc"),
        MsFlags::empty(),
        data.as_deref(),
    )
    .map_err(|e| mnt_nix(format!("proc mount at {dst} failed"), e))?;

    Ok(())
}

fn process_mqueue_mount(entry: &Entry, new_root: &Path) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("mqueue mount requires a dst field".into()))?;

    let target = new_root.join(dst.trim_start_matches('/'));
    fs::create_dir_all(&target)
        .map_err(|e| mnt(format!("failed to create directory for mqueue at {dst}"), e))?;

    mount(
        Some("mqueue"),
        &target,
        Some("mqueue"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| mnt_nix(format!("mqueue mount at {dst} failed"), e))?;

    Ok(())
}

fn process_content_entry(
    entry: &Entry,
    content: &str,
    new_root: &Path,
    staging: &Path,
    content_idx: &mut usize,
) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("content mount requires a dst field".into()))?;

    let staging_file = staging.join(format!("content-{content_idx}"));
    *content_idx += 1;
    fs::write(&staging_file, content)
        .map_err(|e| mnt(format!("failed to write content for {dst}"), e))?;

    let target = new_root.join(dst.trim_start_matches('/'));
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| mnt(format!("failed to create parent dirs for {dst}"), e))?;
    }
    fs::write(&target, "")
        .map_err(|e| mnt(format!("failed to create mount point file for {dst}"), e))?;

    mount(
        Some(staging_file.as_path()),
        &target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| mnt_nix(format!("content bind mount to {dst} failed"), e))?;

    if entry.read_only {
        mount(
            None::<&str>,
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| mnt_nix(format!("read-only remount of content at {dst} failed"), e))?;
    }

    Ok(())
}

fn ensure_mount_point(target: &Path, source: &str) -> Result<(), Error> {
    let source_meta = fs::metadata(source)
        .map_err(|e| mnt(format!("source path does not exist: {source}"), e))?;

    if source_meta.is_dir() {
        fs::create_dir_all(target).map_err(|e| {
            mnt(
                format!(
                    "failed to create directory mount point: {}",
                    target.display()
                ),
                e,
            )
        })?;
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                mnt(
                    format!("failed to create parent dirs for {}", target.display()),
                    e,
                )
            })?;
        }
        fs::write(target, "").map_err(|e| {
            mnt(
                format!("failed to create file mount point: {}", target.display()),
                e,
            )
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_data_empty() {
        let data = MountData::new();
        assert_eq!(data.to_string(), None);
    }

    #[test]
    fn mount_data_single() {
        let mut data = MountData::new();
        data.push("size", "1024").unwrap();
        assert_eq!(data.to_string(), Some("size=1024".to_string()));
    }

    #[test]
    fn mount_data_multiple() {
        let mut data = MountData::new();
        data.push("newinstance", "1").unwrap();
        data.push("ptmxmode", "0666").unwrap();
        data.push("mode", "620").unwrap();
        assert_eq!(
            data.to_string(),
            Some("newinstance=1,ptmxmode=0666,mode=620".to_string())
        );
    }

    #[test]
    fn mount_data_duplicate_key_rejected() {
        let mut data = MountData::new();
        data.push("size", "1024").unwrap();
        let err = data.push("size", "2048").unwrap_err();
        assert!(
            err.to_string().contains("duplicate mount data key: size"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mount_data_preserves_insertion_order() {
        let mut data = MountData::new();
        data.push("subset", "pid").unwrap();
        data.push("hidepid", "invisible").unwrap();
        assert_eq!(
            data.to_string(),
            Some("subset=pid,hidepid=invisible".to_string())
        );
    }
}
