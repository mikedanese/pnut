//! `/dev` setup inside the sandbox filesystem.

use crate::error::Error;
use nix::mount::{MsFlags, mount};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::{mnt, mnt_nix};

/// Set up `/dev` with device nodes, shm, pts, and standard symlinks.
///
/// Called in the child process after fork.
pub(super) fn setup_dev(new_root: &Path) -> Result<(), Error> {
    let dev_dir = new_root.join("dev");
    fs::create_dir_all(&dev_dir).map_err(|e| mnt("failed to create /dev", e))?;

    mount(
        Some("tmpfs"),
        &dev_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .map_err(|e| mnt_nix("failed to mount tmpfs at /dev", e))?;

    let devices = ["null", "zero", "full", "random", "urandom", "tty"];
    for dev in &devices {
        let host_path = format!("/dev/{dev}");
        let target = dev_dir.join(dev);

        fs::write(&target, "")
            .map_err(|e| mnt(format!("failed to create mount point for /dev/{dev}"), e))?;

        mount(
            Some(host_path.as_str()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| mnt_nix(format!("failed to bind mount /dev/{dev}"), e))?;
    }

    // /dev/shm — shared memory tmpfs
    let shm_dir = dev_dir.join("shm");
    fs::create_dir_all(&shm_dir).map_err(|e| mnt("failed to create /dev/shm", e))?;
    mount(
        Some("tmpfs"),
        &shm_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777"),
    )
    .map_err(|e| mnt_nix("failed to mount tmpfs at /dev/shm", e))?;

    // /dev/pts — isolated devpts instance for PTY support
    let pts_dir = dev_dir.join("pts");
    fs::create_dir_all(&pts_dir).map_err(|e| mnt("failed to create /dev/pts", e))?;
    mount(
        Some("devpts"),
        &pts_dir,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
    )
    .map_err(|e| mnt_nix("failed to mount devpts at /dev/pts", e))?;

    // /dev/ptmx -> pts/ptmx (standard devpts setup)
    symlink("pts/ptmx", dev_dir.join("ptmx"))
        .map_err(|e| mnt("failed to create /dev/ptmx symlink", e))?;

    symlink("/proc/self/fd", dev_dir.join("fd"))
        .map_err(|e| mnt("failed to create /dev/fd symlink", e))?;
    symlink("/proc/self/fd/0", dev_dir.join("stdin"))
        .map_err(|e| mnt("failed to create /dev/stdin symlink", e))?;
    symlink("/proc/self/fd/1", dev_dir.join("stdout"))
        .map_err(|e| mnt("failed to create /dev/stdout symlink", e))?;
    symlink("/proc/self/fd/2", dev_dir.join("stderr"))
        .map_err(|e| mnt("failed to create /dev/stderr symlink", e))?;

    Ok(())
}
