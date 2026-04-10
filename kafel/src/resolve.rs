//! Resolution stage: converts the parsed AST into a flat, numeric
//! intermediate representation ready for BPF codegen.
//!
//! This module handles:
//! - Syscall name to number resolution via `libc::SYS_*`
//! - `#define` constant substitution
//! - Argument name to index (0-5) mapping
//! - `USE` reference flattening with cycle detection
//! - Expression simplification and constant folding

use std::collections::{HashMap, HashSet};

use crate::ast::{
    Action as AstAction, ActionBlock, BoolExpr, CmpLhs, CmpOp, Expr as AstExpr,
    PolicyEntry as AstPolicyEntry, PolicyFile, Span,
};
use crate::error::Error;

// ---------------------------------------------------------------------------
// Resolved IR types
// ---------------------------------------------------------------------------

/// The fully resolved policy: a flat list of rules plus a default action.
#[derive(Debug)]
pub struct Policy {
    /// Resolved syscall rules, each with a numeric syscall number.
    pub entries: Vec<PolicyEntry>,
    /// The default action for syscalls not matched by any rule.
    pub default_action: Action,
}

/// A single resolved syscall rule.
#[derive(Debug)]
pub struct PolicyEntry {
    /// Numeric syscall number (from `libc::SYS_*`).
    pub syscall_number: u32,
    /// The action to take when this syscall matches.
    pub action: Action,
    /// Optional filter expression (all identifiers resolved to arg indices
    /// and constants folded).
    pub filter: Option<Expr>,
}

/// A resolved seccomp action mapped to `SECCOMP_RET_*` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Allow,
    Kill,
    KillProcess,
    Log,
    UserNotif,
    Errno(u32),
    Trap(u32),
    Trace(u32),
}

/// A fully resolved expression tree. All identifiers have been replaced
/// with argument indices or numeric constants; all foldable sub-expressions
/// have been reduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A constant numeric value.
    Constant(u64),
    /// A syscall argument by index (0-5).
    Arg(u8),
    /// Boolean constant (result of folding).
    BoolConst(bool),
    /// Comparison: lhs op rhs.
    Compare(Box<Expr>, CmpOp, Box<Expr>),
    /// Masked comparison: (arg & mask) op rhs.
    MaskedCompare {
        arg_index: u8,
        mask: Box<Expr>,
        op: CmpOp,
        rhs: Box<Expr>,
    },
    /// Logical AND.
    And(Box<Expr>, Box<Expr>),
    /// Logical OR.
    Or(Box<Expr>, Box<Expr>),
    /// Logical NOT.
    Not(Box<Expr>),
    /// Bitwise OR of values.
    BitOr(Vec<Expr>),
}

impl Policy {
    /// Add a rule entry to the policy.
    pub fn add_entry(&mut self, entry: PolicyEntry) {
        self.entries.push(entry);
    }

    /// Generate BPF bytecode from this resolved policy.
    pub fn codegen(&self) -> Result<crate::codegen::BpfProgram, Error> {
        crate::codegen::codegen_policy(self)
    }
}

// ---------------------------------------------------------------------------
// Syscall name -> number mapping
// ---------------------------------------------------------------------------

/// Resolve a syscall name to its x86_64 number via `libc::SYS_*` constants.
pub fn resolve_syscall(name: &str) -> Result<u32, Error> {
    // Build the mapping from well-known names. We use a match on string
    // slices rather than a HashMap for zero-allocation lookup. This covers
    // all x86_64 syscalls exposed by libc.
    let nr: i64 = match name {
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "open" => libc::SYS_open,
        "close" => libc::SYS_close,
        "stat" => libc::SYS_stat,
        "fstat" => libc::SYS_fstat,
        "lstat" => libc::SYS_lstat,
        "poll" => libc::SYS_poll,
        "lseek" => libc::SYS_lseek,
        "mmap" => libc::SYS_mmap,
        "mprotect" => libc::SYS_mprotect,
        #[cfg(target_arch = "x86_64")]
        "pkey_mprotect" => libc::SYS_pkey_mprotect,
        "munmap" => libc::SYS_munmap,
        "brk" => libc::SYS_brk,
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "ioctl" => libc::SYS_ioctl,
        "pread64" => libc::SYS_pread64,
        "pwrite64" => libc::SYS_pwrite64,
        "readv" => libc::SYS_readv,
        "writev" => libc::SYS_writev,
        "access" => libc::SYS_access,
        "pipe" => libc::SYS_pipe,
        "select" => libc::SYS_select,
        "sched_yield" => libc::SYS_sched_yield,
        "mremap" => libc::SYS_mremap,
        "msync" => libc::SYS_msync,
        "mincore" => libc::SYS_mincore,
        "madvise" => libc::SYS_madvise,
        "shmget" => libc::SYS_shmget,
        "shmat" => libc::SYS_shmat,
        "shmctl" => libc::SYS_shmctl,
        "dup" => libc::SYS_dup,
        "dup2" => libc::SYS_dup2,
        "pause" => libc::SYS_pause,
        "nanosleep" => libc::SYS_nanosleep,
        "getitimer" => libc::SYS_getitimer,
        "alarm" => libc::SYS_alarm,
        "setitimer" => libc::SYS_setitimer,
        "getpid" => libc::SYS_getpid,
        "sendfile" => libc::SYS_sendfile,
        "socket" => libc::SYS_socket,
        "connect" => libc::SYS_connect,
        "accept" => libc::SYS_accept,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "shutdown" => libc::SYS_shutdown,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "getsockname" => libc::SYS_getsockname,
        "getpeername" => libc::SYS_getpeername,
        "socketpair" => libc::SYS_socketpair,
        "setsockopt" => libc::SYS_setsockopt,
        "getsockopt" => libc::SYS_getsockopt,
        "clone" => libc::SYS_clone,
        "fork" => libc::SYS_fork,
        "vfork" => libc::SYS_vfork,
        "execve" => libc::SYS_execve,
        "exit" => libc::SYS_exit,
        "wait4" => libc::SYS_wait4,
        "kill" => libc::SYS_kill,
        "uname" => libc::SYS_uname,
        "semget" => libc::SYS_semget,
        "semop" => libc::SYS_semop,
        "semctl" => libc::SYS_semctl,
        "shmdt" => libc::SYS_shmdt,
        "msgget" => libc::SYS_msgget,
        "msgsnd" => libc::SYS_msgsnd,
        "msgrcv" => libc::SYS_msgrcv,
        "msgctl" => libc::SYS_msgctl,
        "fcntl" => libc::SYS_fcntl,
        "flock" => libc::SYS_flock,
        "fsync" => libc::SYS_fsync,
        "fdatasync" => libc::SYS_fdatasync,
        "truncate" => libc::SYS_truncate,
        "ftruncate" => libc::SYS_ftruncate,
        "getdents" => libc::SYS_getdents,
        "getcwd" => libc::SYS_getcwd,
        "chdir" => libc::SYS_chdir,
        "fchdir" => libc::SYS_fchdir,
        "rename" => libc::SYS_rename,
        "mkdir" => libc::SYS_mkdir,
        "rmdir" => libc::SYS_rmdir,
        "creat" => libc::SYS_creat,
        "link" => libc::SYS_link,
        "unlink" => libc::SYS_unlink,
        "symlink" => libc::SYS_symlink,
        "readlink" => libc::SYS_readlink,
        "chmod" => libc::SYS_chmod,
        "fchmod" => libc::SYS_fchmod,
        "chown" => libc::SYS_chown,
        "fchown" => libc::SYS_fchown,
        "lchown" => libc::SYS_lchown,
        "umask" => libc::SYS_umask,
        "gettimeofday" => libc::SYS_gettimeofday,
        "getrlimit" => libc::SYS_getrlimit,
        "getrusage" => libc::SYS_getrusage,
        "sysinfo" => libc::SYS_sysinfo,
        "times" => libc::SYS_times,
        "ptrace" => libc::SYS_ptrace,
        "getuid" => libc::SYS_getuid,
        "syslog" => libc::SYS_syslog,
        "getgid" => libc::SYS_getgid,
        "setuid" => libc::SYS_setuid,
        "setgid" => libc::SYS_setgid,
        "geteuid" => libc::SYS_geteuid,
        "getegid" => libc::SYS_getegid,
        "setpgid" => libc::SYS_setpgid,
        "getppid" => libc::SYS_getppid,
        "getpgrp" => libc::SYS_getpgrp,
        "setsid" => libc::SYS_setsid,
        "setreuid" => libc::SYS_setreuid,
        "setregid" => libc::SYS_setregid,
        "getgroups" => libc::SYS_getgroups,
        "setgroups" => libc::SYS_setgroups,
        "setresuid" => libc::SYS_setresuid,
        "getresuid" => libc::SYS_getresuid,
        "setresgid" => libc::SYS_setresgid,
        "getresgid" => libc::SYS_getresgid,
        "getpgid" => libc::SYS_getpgid,
        "setfsuid" => libc::SYS_setfsuid,
        "setfsgid" => libc::SYS_setfsgid,
        "getsid" => libc::SYS_getsid,
        "capget" => libc::SYS_capget,
        "capset" => libc::SYS_capset,
        "rt_sigpending" => libc::SYS_rt_sigpending,
        "rt_sigtimedwait" => libc::SYS_rt_sigtimedwait,
        "rt_sigqueueinfo" => libc::SYS_rt_sigqueueinfo,
        "rt_sigsuspend" => libc::SYS_rt_sigsuspend,
        "sigaltstack" => libc::SYS_sigaltstack,
        "utime" => libc::SYS_utime,
        "mknod" => libc::SYS_mknod,
        "personality" => libc::SYS_personality,
        "ustat" => libc::SYS_ustat,
        "statfs" => libc::SYS_statfs,
        "fstatfs" => libc::SYS_fstatfs,
        "sysfs" => libc::SYS_sysfs,
        "getpriority" => libc::SYS_getpriority,
        "setpriority" => libc::SYS_setpriority,
        "sched_setparam" => libc::SYS_sched_setparam,
        "sched_getparam" => libc::SYS_sched_getparam,
        "sched_setscheduler" => libc::SYS_sched_setscheduler,
        "sched_getscheduler" => libc::SYS_sched_getscheduler,
        "sched_get_priority_max" => libc::SYS_sched_get_priority_max,
        "sched_get_priority_min" => libc::SYS_sched_get_priority_min,
        "sched_rr_get_interval" => libc::SYS_sched_rr_get_interval,
        "mlock" => libc::SYS_mlock,
        "munlock" => libc::SYS_munlock,
        "mlockall" => libc::SYS_mlockall,
        "munlockall" => libc::SYS_munlockall,
        "vhangup" => libc::SYS_vhangup,
        "pivot_root" => libc::SYS_pivot_root,
        "prctl" => libc::SYS_prctl,
        "arch_prctl" => libc::SYS_arch_prctl,
        "adjtimex" => libc::SYS_adjtimex,
        "setrlimit" => libc::SYS_setrlimit,
        "chroot" => libc::SYS_chroot,
        "sync" => libc::SYS_sync,
        "acct" => libc::SYS_acct,
        "settimeofday" => libc::SYS_settimeofday,
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "swapon" => libc::SYS_swapon,
        "swapoff" => libc::SYS_swapoff,
        "reboot" => libc::SYS_reboot,
        "sethostname" => libc::SYS_sethostname,
        "setdomainname" => libc::SYS_setdomainname,
        "ioperm" => libc::SYS_ioperm,
        "init_module" => libc::SYS_init_module,
        "delete_module" => libc::SYS_delete_module,
        "quotactl" => libc::SYS_quotactl,
        "gettid" => libc::SYS_gettid,
        "readahead" => libc::SYS_readahead,
        "setxattr" => libc::SYS_setxattr,
        "lsetxattr" => libc::SYS_lsetxattr,
        "fsetxattr" => libc::SYS_fsetxattr,
        "getxattr" => libc::SYS_getxattr,
        "lgetxattr" => libc::SYS_lgetxattr,
        "fgetxattr" => libc::SYS_fgetxattr,
        "listxattr" => libc::SYS_listxattr,
        "llistxattr" => libc::SYS_llistxattr,
        "flistxattr" => libc::SYS_flistxattr,
        "removexattr" => libc::SYS_removexattr,
        "lremovexattr" => libc::SYS_lremovexattr,
        "fremovexattr" => libc::SYS_fremovexattr,
        "tkill" => libc::SYS_tkill,
        "time" => libc::SYS_time,
        "futex" => libc::SYS_futex,
        "sched_setaffinity" => libc::SYS_sched_setaffinity,
        "sched_getaffinity" => libc::SYS_sched_getaffinity,
        "io_setup" => libc::SYS_io_setup,
        "io_destroy" => libc::SYS_io_destroy,
        "io_getevents" => libc::SYS_io_getevents,
        "io_submit" => libc::SYS_io_submit,
        "io_cancel" => libc::SYS_io_cancel,
        "epoll_create" => libc::SYS_epoll_create,
        "getdents64" => libc::SYS_getdents64,
        "set_tid_address" => libc::SYS_set_tid_address,
        "restart_syscall" => libc::SYS_restart_syscall,
        "semtimedop" => libc::SYS_semtimedop,
        "fadvise64" => libc::SYS_fadvise64,
        "timer_create" => libc::SYS_timer_create,
        "timer_settime" => libc::SYS_timer_settime,
        "timer_gettime" => libc::SYS_timer_gettime,
        "timer_getoverrun" => libc::SYS_timer_getoverrun,
        "timer_delete" => libc::SYS_timer_delete,
        "clock_settime" => libc::SYS_clock_settime,
        "clock_gettime" => libc::SYS_clock_gettime,
        "clock_getres" => libc::SYS_clock_getres,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "exit_group" => libc::SYS_exit_group,
        "epoll_wait" => libc::SYS_epoll_wait,
        "epoll_ctl" => libc::SYS_epoll_ctl,
        "tgkill" => libc::SYS_tgkill,
        "utimes" => libc::SYS_utimes,
        "mbind" => libc::SYS_mbind,
        "set_mempolicy" => libc::SYS_set_mempolicy,
        "get_mempolicy" => libc::SYS_get_mempolicy,
        "mq_open" => libc::SYS_mq_open,
        "mq_unlink" => libc::SYS_mq_unlink,
        "mq_timedsend" => libc::SYS_mq_timedsend,
        "mq_timedreceive" => libc::SYS_mq_timedreceive,
        "mq_notify" => libc::SYS_mq_notify,
        "mq_getsetattr" => libc::SYS_mq_getsetattr,
        "kexec_load" => libc::SYS_kexec_load,
        "waitid" => libc::SYS_waitid,
        "add_key" => libc::SYS_add_key,
        "request_key" => libc::SYS_request_key,
        "keyctl" => libc::SYS_keyctl,
        "ioprio_set" => libc::SYS_ioprio_set,
        "ioprio_get" => libc::SYS_ioprio_get,
        "inotify_init" => libc::SYS_inotify_init,
        "inotify_add_watch" => libc::SYS_inotify_add_watch,
        "inotify_rm_watch" => libc::SYS_inotify_rm_watch,
        "migrate_pages" => libc::SYS_migrate_pages,
        "openat" => libc::SYS_openat,
        "mkdirat" => libc::SYS_mkdirat,
        "mknodat" => libc::SYS_mknodat,
        "fchownat" => libc::SYS_fchownat,
        "futimesat" => libc::SYS_futimesat,
        "newfstatat" => libc::SYS_newfstatat,
        "unlinkat" => libc::SYS_unlinkat,
        "renameat" => libc::SYS_renameat,
        "linkat" => libc::SYS_linkat,
        "symlinkat" => libc::SYS_symlinkat,
        "readlinkat" => libc::SYS_readlinkat,
        "fchmodat" => libc::SYS_fchmodat,
        "faccessat" => libc::SYS_faccessat,
        "pselect6" => libc::SYS_pselect6,
        "ppoll" => libc::SYS_ppoll,
        "unshare" => libc::SYS_unshare,
        "set_robust_list" => libc::SYS_set_robust_list,
        "get_robust_list" => libc::SYS_get_robust_list,
        "splice" => libc::SYS_splice,
        "tee" => libc::SYS_tee,
        "sync_file_range" => libc::SYS_sync_file_range,
        "vmsplice" => libc::SYS_vmsplice,
        "move_pages" => libc::SYS_move_pages,
        "utimensat" => libc::SYS_utimensat,
        "epoll_pwait" => libc::SYS_epoll_pwait,
        "signalfd" => libc::SYS_signalfd,
        "timerfd_create" => libc::SYS_timerfd_create,
        "eventfd" => libc::SYS_eventfd,
        "fallocate" => libc::SYS_fallocate,
        "timerfd_settime" => libc::SYS_timerfd_settime,
        "timerfd_gettime" => libc::SYS_timerfd_gettime,
        "accept4" => libc::SYS_accept4,
        "signalfd4" => libc::SYS_signalfd4,
        "eventfd2" => libc::SYS_eventfd2,
        "epoll_create1" => libc::SYS_epoll_create1,
        "dup3" => libc::SYS_dup3,
        "pipe2" => libc::SYS_pipe2,
        "inotify_init1" => libc::SYS_inotify_init1,
        "preadv" => libc::SYS_preadv,
        "pwritev" => libc::SYS_pwritev,
        "rt_tgsigqueueinfo" => libc::SYS_rt_tgsigqueueinfo,
        "perf_event_open" => libc::SYS_perf_event_open,
        "recvmmsg" => libc::SYS_recvmmsg,
        "fanotify_init" => libc::SYS_fanotify_init,
        "fanotify_mark" => libc::SYS_fanotify_mark,
        "prlimit64" => libc::SYS_prlimit64,
        "name_to_handle_at" => libc::SYS_name_to_handle_at,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "clock_adjtime" => libc::SYS_clock_adjtime,
        "syncfs" => libc::SYS_syncfs,
        "sendmmsg" => libc::SYS_sendmmsg,
        "setns" => libc::SYS_setns,
        "getcpu" => libc::SYS_getcpu,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "kcmp" => libc::SYS_kcmp,
        "finit_module" => libc::SYS_finit_module,
        "sched_setattr" => libc::SYS_sched_setattr,
        "sched_getattr" => libc::SYS_sched_getattr,
        "renameat2" => libc::SYS_renameat2,
        "seccomp" => libc::SYS_seccomp,
        "getrandom" => libc::SYS_getrandom,
        "memfd_create" => libc::SYS_memfd_create,
        "bpf" => libc::SYS_bpf,
        "execveat" => libc::SYS_execveat,
        "membarrier" => libc::SYS_membarrier,
        "mlock2" => libc::SYS_mlock2,
        "copy_file_range" => libc::SYS_copy_file_range,
        "preadv2" => libc::SYS_preadv2,
        "pwritev2" => libc::SYS_pwritev2,
        "statx" => libc::SYS_statx,
        "rseq" => libc::SYS_rseq,
        "pidfd_send_signal" => libc::SYS_pidfd_send_signal,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "open_tree" => libc::SYS_open_tree,
        "move_mount" => libc::SYS_move_mount,
        "fsopen" => libc::SYS_fsopen,
        "fsconfig" => libc::SYS_fsconfig,
        "fsmount" => libc::SYS_fsmount,
        "fspick" => libc::SYS_fspick,
        "pidfd_open" => libc::SYS_pidfd_open,
        "clone3" => libc::SYS_clone3,
        "close_range" => libc::SYS_close_range,
        "pidfd_getfd" => libc::SYS_pidfd_getfd,
        "faccessat2" => libc::SYS_faccessat2,
        "process_madvise" => libc::SYS_process_madvise,
        "epoll_pwait2" => libc::SYS_epoll_pwait2,
        "mount_setattr" => libc::SYS_mount_setattr,
        "landlock_create_ruleset" => libc::SYS_landlock_create_ruleset,
        "landlock_add_rule" => libc::SYS_landlock_add_rule,
        "landlock_restrict_self" => libc::SYS_landlock_restrict_self,
        "memfd_secret" => libc::SYS_memfd_secret,
        "process_mrelease" => libc::SYS_process_mrelease,
        _ => {
            return Err(Error::UnknownSyscall {
                name: name.to_string(),
                span: None,
            });
        }
    };
    Ok(nr as u32)
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Holds resolution context: define constants and policy lookup.
struct Resolver<'a> {
    /// `#define` name -> resolved numeric value.
    defines: HashMap<&'a str, u64>,
    /// Policy name -> index in the PolicyFile's policies vec.
    policy_index: HashMap<&'a str, usize>,
    /// The original policy file.
    policy_file: &'a PolicyFile,
}

impl<'a> Resolver<'a> {
    fn new(pf: &'a PolicyFile) -> Result<Self, Error> {
        let mut defines = HashMap::new();
        // First pass: resolve all defines. Support forward references by
        // iterating until stable (defines are typically small and acyclic).
        // For simplicity and safety, we do a topological resolution.
        let raw_defines: HashMap<&str, &AstExpr> =
            pf.defines.iter().map(|(n, e)| (n.as_str(), e)).collect();

        // Resolve each define, substituting other defines as needed.
        for (name, expr) in &pf.defines {
            if !defines.contains_key(name.as_str()) {
                let value = Self::resolve_define_expr(
                    expr,
                    &raw_defines,
                    &mut defines,
                    &mut HashSet::new(),
                )?;
                defines.insert(name.as_str(), value);
            }
        }

        let mut policy_index = HashMap::new();
        for (i, p) in pf.policies.iter().enumerate() {
            policy_index.insert(p.name.as_str(), i);
        }

        Ok(Resolver {
            defines,
            policy_index,
            policy_file: pf,
        })
    }

    /// Recursively resolve a define expression to a numeric value.
    fn resolve_define_expr(
        expr: &'a AstExpr,
        raw_defines: &HashMap<&'a str, &'a AstExpr>,
        resolved: &mut HashMap<&'a str, u64>,
        in_progress: &mut HashSet<&'a str>,
    ) -> Result<u64, Error> {
        match expr {
            AstExpr::Number(n) => Ok(*n),
            AstExpr::Ident(name, span) => {
                if let Some(&val) = resolved.get(name.as_str()) {
                    return Ok(val);
                }
                if in_progress.contains(name.as_str()) {
                    return Err(Error::UndefinedIdentifier {
                        name: name.clone(),
                        span: Some(*span),
                    });
                }
                if let Some(def_expr) = raw_defines.get(name.as_str()) {
                    in_progress.insert(name.as_str());
                    let val =
                        Self::resolve_define_expr(def_expr, raw_defines, resolved, in_progress)?;
                    in_progress.remove(name.as_str());
                    resolved.insert(name.as_str(), val);
                    Ok(val)
                } else {
                    Err(Error::UndefinedIdentifier {
                        name: name.clone(),
                        span: Some(*span),
                    })
                }
            }
            AstExpr::BitOr(parts) => {
                let mut result = 0u64;
                for part in parts {
                    result |= Self::resolve_define_expr(part, raw_defines, resolved, in_progress)?;
                }
                Ok(result)
            }
        }
    }

    /// Resolve a value expression, substituting defines and folding constants.
    /// Argument names are NOT resolved here (they're handled in bool_expr context).
    fn resolve_expr(&self, expr: &AstExpr, arg_map: &HashMap<&str, u8>) -> Result<Expr, Error> {
        match expr {
            AstExpr::Number(n) => Ok(Expr::Constant(*n)),
            AstExpr::Ident(name, span) => {
                // First check if it's a #define constant
                if let Some(&val) = self.defines.get(name.as_str()) {
                    return Ok(Expr::Constant(val));
                }
                // Then check if it's an argument name
                if let Some(&idx) = arg_map.get(name.as_str()) {
                    return Ok(Expr::Arg(idx));
                }
                Err(Error::UndefinedIdentifier {
                    name: name.clone(),
                    span: Some(*span),
                })
            }
            AstExpr::BitOr(parts) => {
                let resolved: Vec<Expr> = parts
                    .iter()
                    .map(|p| self.resolve_expr(p, arg_map))
                    .collect::<Result<_, _>>()?;

                // Try to fold all-constant BitOr
                if resolved.iter().all(|e| matches!(e, Expr::Constant(_))) {
                    let val = resolved.iter().fold(0u64, |acc, e| match e {
                        Expr::Constant(n) => acc | n,
                        _ => unreachable!(),
                    });
                    Ok(Expr::Constant(val))
                } else {
                    Ok(Expr::BitOr(resolved))
                }
            }
        }
    }

    /// Resolve a boolean expression, mapping argument names to indices and
    /// folding constants.
    fn resolve_bool_expr(
        &self,
        expr: &BoolExpr,
        arg_map: &HashMap<&str, u8>,
        syscall_name: &str,
    ) -> Result<Expr, Error> {
        match expr {
            BoolExpr::Compare(lhs, op, rhs) => {
                let resolved_rhs = self.resolve_expr(rhs, arg_map)?;
                match lhs {
                    CmpLhs::Arg(name, span) => {
                        // Check if it's an argument
                        if let Some(&idx) = arg_map.get(name.as_str()) {
                            let resolved_lhs = Expr::Arg(idx);
                            Ok(simplify_compare(resolved_lhs, *op, resolved_rhs))
                        } else if self.defines.contains_key(name.as_str()) {
                            // It's a define used on the LHS of a comparison
                            let val = self.defines[name.as_str()];
                            let resolved_lhs = Expr::Constant(val);
                            Ok(simplify_compare(resolved_lhs, *op, resolved_rhs))
                        } else {
                            Err(Error::UndeclaredArgument {
                                name: name.clone(),
                                syscall: syscall_name.to_string(),
                                span: Some(*span),
                            })
                        }
                    }
                    CmpLhs::Masked(name, span, mask) => {
                        let idx = arg_map.get(name.as_str()).copied().ok_or_else(|| {
                            Error::UndeclaredArgument {
                                name: name.clone(),
                                syscall: syscall_name.to_string(),
                                span: Some(*span),
                            }
                        })?;
                        let resolved_mask = self.resolve_expr(mask, arg_map)?;
                        Ok(Expr::MaskedCompare {
                            arg_index: idx,
                            mask: Box::new(resolved_mask),
                            op: *op,
                            rhs: Box::new(resolved_rhs),
                        })
                    }
                }
            }
            BoolExpr::And(a, b) => {
                let ra = self.resolve_bool_expr(a, arg_map, syscall_name)?;
                let rb = self.resolve_bool_expr(b, arg_map, syscall_name)?;
                Ok(simplify_and(ra, rb))
            }
            BoolExpr::Or(a, b) => {
                let ra = self.resolve_bool_expr(a, arg_map, syscall_name)?;
                let rb = self.resolve_bool_expr(b, arg_map, syscall_name)?;
                Ok(simplify_or(ra, rb))
            }
            BoolExpr::Not(inner) => {
                let ri = self.resolve_bool_expr(inner, arg_map, syscall_name)?;
                Ok(simplify_not(ri))
            }
            BoolExpr::Literal(val) => Ok(Expr::BoolConst(*val)),
        }
    }

    fn resolve_action_value(&self, expr: &AstExpr) -> Result<u32, Error> {
        let value = match expr {
            AstExpr::Number(n) => *n,
            AstExpr::Ident(name, span) => {
                *self
                    .defines
                    .get(name.as_str())
                    .ok_or_else(|| Error::UndefinedIdentifier {
                        name: name.clone(),
                        span: Some(*span),
                    })?
            }
            AstExpr::BitOr(parts) => {
                let mut result = 0u64;
                for part in parts {
                    result |= self.resolve_action_value(part)? as u64;
                }
                result
            }
        };
        Ok(value as u32)
    }

    /// Resolve an AST Action to a resolved Action.
    fn resolve_action(&self, action: &AstAction) -> Result<Action, Error> {
        match action {
            AstAction::Allow => Ok(Action::Allow),
            AstAction::Kill => Ok(Action::Kill),
            AstAction::KillProcess => Ok(Action::KillProcess),
            AstAction::Log => Ok(Action::Log),
            AstAction::UserNotif => Ok(Action::UserNotif),
            AstAction::Errno(expr) => Ok(Action::Errno(self.resolve_action_value(expr)?)),
            AstAction::Trap(expr) => Ok(Action::Trap(self.resolve_action_value(expr)?)),
            AstAction::Trace(expr) => Ok(Action::Trace(self.resolve_action_value(expr)?)),
        }
    }

    /// Flatten a policy by name, recursively expanding USE references.
    /// Returns a list of (action_block) entries with all USE refs inlined.
    ///
    /// `ref_span` is the source span of the `USE` that brought us here, used
    /// to attach a location to `CircularUse` / `UndefinedPolicy` errors. It
    /// is `None` for the top-level entry into `resolve`.
    fn flatten_policy(
        &self,
        policy_name: &str,
        ref_span: Option<Span>,
        visiting: &mut HashSet<String>,
        entries: &mut Vec<(Action, Vec<PolicyEntry>)>,
    ) -> Result<(), Error> {
        if !visiting.insert(policy_name.to_string()) {
            return Err(Error::CircularUse {
                policy: policy_name.to_string(),
                span: ref_span,
            });
        }

        let idx = self
            .policy_index
            .get(policy_name)
            .ok_or_else(|| Error::UndefinedPolicy {
                name: policy_name.to_string(),
                span: ref_span,
            })?;
        let policy = &self.policy_file.policies[*idx];

        for entry in &policy.entries {
            match entry {
                AstPolicyEntry::ActionBlock(block) => {
                    let action = self.resolve_action(&block.action)?;
                    let resolved_rules = self.resolve_action_block(block, &action)?;
                    entries.push((action, resolved_rules));
                }
                AstPolicyEntry::UseRef(ref_name, span) => {
                    self.flatten_policy(ref_name, Some(*span), visiting, entries)?;
                }
            }
        }

        visiting.remove(policy_name);
        Ok(())
    }

    /// Resolve all syscall rules in an action block.
    fn resolve_action_block(
        &self,
        block: &ActionBlock,
        action: &Action,
    ) -> Result<Vec<PolicyEntry>, Error> {
        let mut resolved = Vec::new();
        for rule in &block.rules {
            let syscall_number = resolve_syscall(&rule.name).map_err(|e| match e {
                Error::UnknownSyscall { name, .. } => Error::UnknownSyscall {
                    name,
                    span: Some(rule.name_span),
                },
                other => other,
            })?;

            // Build argument name -> index map
            let arg_map: HashMap<&str, u8> = rule
                .args
                .iter()
                .enumerate()
                .map(|(i, name)| (name.as_str(), i as u8))
                .collect();

            let filter = if let Some(ref filter_expr) = rule.filter {
                Some(self.resolve_bool_expr(filter_expr, &arg_map, &rule.name)?)
            } else {
                None
            };

            resolved.push(PolicyEntry {
                syscall_number,
                action: action.clone(),
                filter,
            });
        }
        Ok(resolved)
    }
}

// ---------------------------------------------------------------------------
// Expression simplification
// ---------------------------------------------------------------------------

/// Simplify a comparison, folding if both sides are constants.
fn simplify_compare(lhs: Expr, op: CmpOp, rhs: Expr) -> Expr {
    if let (Expr::Constant(a), Expr::Constant(b)) = (&lhs, &rhs) {
        let result = match op {
            CmpOp::Eq => a == b,
            CmpOp::Ne => a != b,
            CmpOp::Lt => a < b,
            CmpOp::Le => a <= b,
            CmpOp::Gt => a > b,
            CmpOp::Ge => a >= b,
        };
        return Expr::BoolConst(result);
    }
    Expr::Compare(Box::new(lhs), op, Box::new(rhs))
}

/// Simplify AND, handling boolean constants and identity/annihilator cases.
fn simplify_and(a: Expr, b: Expr) -> Expr {
    match (&a, &b) {
        (Expr::BoolConst(true), _) => b,
        (_, Expr::BoolConst(true)) => a,
        (Expr::BoolConst(false), _) | (_, Expr::BoolConst(false)) => Expr::BoolConst(false),
        _ => Expr::And(Box::new(a), Box::new(b)),
    }
}

/// Simplify OR, handling boolean constants and identity/annihilator cases.
fn simplify_or(a: Expr, b: Expr) -> Expr {
    match (&a, &b) {
        (Expr::BoolConst(false), _) => b,
        (_, Expr::BoolConst(false)) => a,
        (Expr::BoolConst(true), _) | (_, Expr::BoolConst(true)) => Expr::BoolConst(true),
        _ => Expr::Or(Box::new(a), Box::new(b)),
    }
}

/// Simplify NOT, handling boolean constants and double negation.
fn simplify_not(expr: Expr) -> Expr {
    match expr {
        Expr::BoolConst(b) => Expr::BoolConst(!b),
        Expr::Not(inner) => *inner, // double negation elimination
        other => Expr::Not(Box::new(other)),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Resolve a parsed policy file into a flat list of numeric rules.
///
/// This is the main entry point for the resolution stage. It:
/// 1. Resolves `#define` constants
/// 2. Flattens `USE` references (with cycle detection)
/// 3. Resolves syscall names to numbers
/// 4. Maps argument names to indices
/// 5. Folds constant expressions
pub fn resolve(policy_file: &PolicyFile) -> Result<Policy, Error> {
    let resolver = Resolver::new(policy_file)?;

    let use_stmt = policy_file.use_stmt.as_ref().ok_or_else(|| Error::Parse {
        message: "no top-level USE statement found".to_string(),
        span: None,
    })?;

    let default_action = resolver.resolve_action(&use_stmt.default_action)?;

    let mut all_entries = Vec::new();
    let mut visiting = HashSet::new();

    for (policy_name, policy_span) in &use_stmt.policies {
        let mut policy_entries = Vec::new();
        resolver.flatten_policy(
            policy_name,
            Some(*policy_span),
            &mut visiting,
            &mut policy_entries,
        )?;
        for (_action, rules) in policy_entries {
            all_entries.extend(rules);
        }
    }

    Ok(Policy {
        entries: all_entries,
        default_action,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_and_validate;

    /// Helper: parse and resolve a policy string.
    fn parse_and_resolve(input: &str) -> Result<Policy, Error> {
        let pf = parse_and_validate(input)?;
        resolve(&pf)
    }

    #[test]
    fn resolve_simple_policy() {
        let input = r#"
            POLICY test {
                ALLOW { read, write, close }
                KILL { ptrace }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        assert_eq!(resolved.entries.len(), 4);
        assert_eq!(resolved.entries[0].syscall_number, libc::SYS_read as u32);
        assert_eq!(resolved.entries[1].syscall_number, libc::SYS_write as u32);
        assert_eq!(resolved.entries[2].syscall_number, libc::SYS_close as u32);
        assert_eq!(resolved.entries[3].syscall_number, libc::SYS_ptrace as u32);
        assert!(matches!(resolved.entries[0].action, Action::Allow));
        assert!(matches!(resolved.entries[3].action, Action::Kill));
        assert!(matches!(resolved.default_action, Action::Kill));
    }

    #[test]
    fn resolve_define_substitution() {
        let input = r#"
            #define STDOUT 1

            POLICY test {
                ALLOW {
                    write(fd, buf, count) { fd == STDOUT }
                }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        assert_eq!(resolved.entries.len(), 1);
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        // fd (arg0) == 1 (resolved from STDOUT)
        match filter {
            Expr::Compare(lhs, CmpOp::Eq, rhs) => {
                assert!(matches!(lhs.as_ref(), Expr::Arg(0)));
                assert!(matches!(rhs.as_ref(), Expr::Constant(1)));
            }
            other => panic!("expected Compare, got {other:?}"),
        }
    }

    #[test]
    fn resolve_define_chain() {
        // STDERR references STDOUT+1, but more practically, defines can
        // reference other defines.
        let input = r#"
            #define BASE 0
            #define STDOUT 1

            POLICY test {
                ALLOW {
                    write(fd, buf, count) { fd == STDOUT }
                }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        match filter {
            Expr::Compare(_, CmpOp::Eq, rhs) => {
                assert!(matches!(rhs.as_ref(), Expr::Constant(1)));
            }
            other => panic!("expected Compare, got {other:?}"),
        }
    }

    #[test]
    fn resolve_unknown_syscall() {
        let input = r#"
            POLICY test {
                ALLOW { not_a_real_syscall }
            }
            USE test DEFAULT KILL
        "#;
        let err = parse_and_resolve(input).unwrap_err();
        match &err {
            Error::UnknownSyscall { name, .. } => {
                assert_eq!(name, "not_a_real_syscall");
            }
            other => panic!("expected UnknownSyscall, got {other}"),
        }
        // Verify Display impl works
        let msg = err.to_string();
        assert!(msg.contains("not_a_real_syscall"), "error message: {msg}");
    }

    #[test]
    fn resolve_circular_use() {
        let input = r#"
            POLICY a {
                USE b
            }
            POLICY b {
                USE a
            }
            USE a DEFAULT KILL
        "#;
        let err = parse_and_resolve(input).unwrap_err();
        match &err {
            Error::CircularUse { policy, .. } => {
                assert_eq!(policy, "a");
            }
            other => panic!("expected CircularUse, got {other}"),
        }
    }

    #[test]
    fn resolve_argument_mapping() {
        let input = r#"
            POLICY test {
                ALLOW {
                    write(fd, buf, count) { fd == 1 && count > 4096 }
                }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        // Should be And(Compare(Arg(0), Eq, Constant(1)), Compare(Arg(2), Gt, Constant(4096)))
        match filter {
            Expr::And(lhs, rhs) => {
                match lhs.as_ref() {
                    Expr::Compare(l, CmpOp::Eq, r) => {
                        assert!(matches!(l.as_ref(), Expr::Arg(0))); // fd -> arg0
                        assert!(matches!(r.as_ref(), Expr::Constant(1)));
                    }
                    other => panic!("expected Compare for lhs, got {other:?}"),
                }
                match rhs.as_ref() {
                    Expr::Compare(l, CmpOp::Gt, r) => {
                        assert!(matches!(l.as_ref(), Expr::Arg(2))); // count -> arg2
                        assert!(matches!(r.as_ref(), Expr::Constant(4096)));
                    }
                    other => panic!("expected Compare for rhs, got {other:?}"),
                }
            }
            other => panic!("expected And, got {other:?}"),
        }
    }

    #[test]
    fn resolve_undeclared_argument() {
        let input = r#"
            POLICY test {
                ALLOW {
                    write(fd, buf, count) { flags == 1 }
                }
            }
            USE test DEFAULT KILL
        "#;
        let err = parse_and_resolve(input).unwrap_err();
        match &err {
            Error::UndeclaredArgument { name, syscall, .. } => {
                assert_eq!(name, "flags");
                assert_eq!(syscall, "write");
            }
            other => panic!("expected UndeclaredArgument, got {other}"),
        }
    }

    #[test]
    fn resolve_constant_folding_bitor() {
        let input = r#"
            POLICY test {
                ALLOW {
                    write(fd, buf, count) { fd == 0x1|0x2 }
                }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        match filter {
            Expr::Compare(_, CmpOp::Eq, rhs) => {
                assert!(
                    matches!(rhs.as_ref(), Expr::Constant(3)),
                    "expected Constant(3), got {rhs:?}"
                );
            }
            other => panic!("expected Compare, got {other:?}"),
        }
    }

    #[test]
    fn resolve_constant_folding_not_false() {
        // !false should fold to true, which in a boolean context becomes BoolConst(true)
        // We need a policy that exercises this. Since our parser doesn't support bare
        // `true`/`false` keywords, we test via the simplification of `!(1 == 2)` which
        // should fold: 1==2 -> false, !false -> true.
        let input = r#"
            #define A 1
            #define B 1

            POLICY test {
                ALLOW {
                    write(fd, buf, count) { !(A == 2) }
                }
            }
            USE test DEFAULT KILL
        "#;
        // A==2 is false (1 != 2), so !(A==2) -> !false -> true
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        assert!(
            matches!(filter, Expr::BoolConst(true)),
            "expected BoolConst(true), got {filter:?}"
        );
    }

    #[test]
    fn resolve_constant_folding_not_true_to_false() {
        let input = r#"
            #define A 1

            POLICY test {
                ALLOW {
                    write(fd, buf, count) { !(A == 1) }
                }
            }
            USE test DEFAULT KILL
        "#;
        // A==1 is true, so !(A==1) -> !true -> false
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        assert!(
            matches!(filter, Expr::BoolConst(false)),
            "expected BoolConst(false), got {filter:?}"
        );
    }

    #[test]
    fn resolve_use_flattening() {
        let input = r#"
            POLICY io {
                ALLOW { read, write }
            }
            POLICY net {
                ALLOW { socket, connect }
            }
            POLICY combined {
                USE io,
                USE net
            }
            USE combined DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        assert_eq!(resolved.entries.len(), 4);
        let names: Vec<u32> = resolved.entries.iter().map(|e| e.syscall_number).collect();
        assert_eq!(
            names,
            vec![
                libc::SYS_read as u32,
                libc::SYS_write as u32,
                libc::SYS_socket as u32,
                libc::SYS_connect as u32,
            ]
        );
    }

    #[test]
    fn resolve_errno_action() {
        let input = r#"
            #define ENOENT 2
            POLICY test {
                ERRNO(ENOENT) { execve }
            }
            USE test DEFAULT ALLOW
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        assert!(matches!(resolved.entries[0].action, Action::Errno(2)));
    }

    #[test]
    fn resolve_trace_action_bitor_define() {
        let input = r#"
            #define BASE 0x1000
            #define EXTRA 0x2
            POLICY test {
                TRACE(BASE | EXTRA) { execve }
            }
            USE test DEFAULT ALLOW
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        assert!(matches!(resolved.entries[0].action, Action::Trace(0x1002)));
    }

    #[test]
    fn resolve_masked_comparison() {
        let input = r#"
            POLICY test {
                ALLOW {
                    mmap(addr, len, prot, flags, fd, offset) {
                        (prot & 0x4) == 0
                    }
                }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        match filter {
            Expr::MaskedCompare {
                arg_index,
                mask,
                op,
                rhs,
            } => {
                assert_eq!(*arg_index, 2); // prot -> arg2
                assert!(matches!(mask.as_ref(), Expr::Constant(0x4)));
                assert_eq!(*op, CmpOp::Eq);
                assert!(matches!(rhs.as_ref(), Expr::Constant(0)));
            }
            other => panic!("expected MaskedCompare, got {other:?}"),
        }
    }

    #[test]
    fn resolve_bitwise_identity_folding() {
        // Test that bitwise OR with defines folds to a constant
        let input = r#"
            #define O_RDWR 2
            #define O_CREAT 64

            POLICY test {
                ALLOW {
                    open(path, flags, mode) {
                        flags == O_RDWR|O_CREAT
                    }
                }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        match filter {
            Expr::Compare(_, CmpOp::Eq, rhs) => {
                assert!(
                    matches!(rhs.as_ref(), Expr::Constant(66)),
                    "expected 2|64=66, got {rhs:?}"
                );
            }
            other => panic!("expected Compare, got {other:?}"),
        }
    }

    #[test]
    fn resolve_complex_boolean() {
        let input = r#"
            POLICY test {
                ALLOW {
                    write(fd, buf, count) {
                        (fd == 1 || fd == 2) && (count < 4096 || buf == 0)
                    }
                }
            }
            USE test DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        let filter = resolved.entries[0].filter.as_ref().unwrap();
        // Top level should be And(Or(...), Or(...))
        match filter {
            Expr::And(lhs, rhs) => {
                assert!(matches!(lhs.as_ref(), Expr::Or(_, _)));
                assert!(matches!(rhs.as_ref(), Expr::Or(_, _)));
            }
            other => panic!("expected And(Or, Or), got {other:?}"),
        }
    }

    #[test]
    fn resolve_documented_example() {
        // Full example from the module doc comment
        let input = r#"
            #define STDOUT 1
            #define STDERR 2

            POLICY stdio {
                ALLOW {
                    read(fd, buf, count) { fd == 0 },
                    write(fd, buf, count) { fd == STDOUT || fd == STDERR },
                    close, dup, dup2, fstat,
                }
            }

            POLICY deny_dangerous {
                KILL { ptrace, process_vm_readv, process_vm_writev }
                ERRNO(1) { execve, execveat }
            }

            USE stdio, deny_dangerous DEFAULT KILL
        "#;
        let resolved = parse_and_resolve(input).unwrap();
        // stdio: read, write, close, dup, dup2, fstat = 6
        // deny_dangerous: ptrace, process_vm_readv, process_vm_writev, execve, execveat = 5
        assert_eq!(resolved.entries.len(), 11);
        assert!(matches!(resolved.default_action, Action::Kill));

        // Verify STDOUT was resolved in the write filter
        let write_entry = &resolved.entries[1]; // write is second
        assert_eq!(write_entry.syscall_number, libc::SYS_write as u32);
        let filter = write_entry.filter.as_ref().unwrap();
        // Should be Or(Compare(Arg(0), Eq, Constant(1)), Compare(Arg(0), Eq, Constant(2)))
        match filter {
            Expr::Or(lhs, rhs) => {
                match lhs.as_ref() {
                    Expr::Compare(_, CmpOp::Eq, r) => {
                        assert!(matches!(r.as_ref(), Expr::Constant(1))); // STDOUT
                    }
                    other => panic!("expected Compare for STDOUT, got {other:?}"),
                }
                match rhs.as_ref() {
                    Expr::Compare(_, CmpOp::Eq, r) => {
                        assert!(matches!(r.as_ref(), Expr::Constant(2))); // STDERR
                    }
                    other => panic!("expected Compare for STDERR, got {other:?}"),
                }
            }
            other => panic!("expected Or, got {other:?}"),
        }
    }

    #[test]
    fn error_display_impl() {
        // Verify Display implementations produce meaningful messages
        let errors = vec![
            Error::Parse {
                message: "unexpected token at 1:5".to_string(),
                span: None,
            },
            Error::UnknownSyscall {
                name: "fake_syscall".to_string(),
                span: None,
            },
            Error::UndefinedIdentifier {
                name: "UNKNOWN".to_string(),
                span: None,
            },
            Error::UndeclaredArgument {
                name: "flags".to_string(),
                syscall: "write".to_string(),
                span: None,
            },
            Error::CircularUse {
                policy: "a".to_string(),
                span: None,
            },
            Error::UndefinedPolicy {
                name: "missing".to_string(),
                span: None,
            },
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Display for {err:?} produced empty string");
        }
        // Verify Error trait is implemented
        let err: &dyn std::error::Error = &errors[0];
        let _ = err.to_string();
    }
}
