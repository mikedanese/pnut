//! Tests that all BUILTIN_PRELUDE policies compile correctly.

use kafel::{CompileOptions, Error};

fn builtin_options() -> CompileOptions {
    CompileOptions::new().with_prelude(kafel::BUILTIN_PRELUDE)
}

#[test]
fn builtin_prelude_exports_compile() {
    let mut names = vec![
        "allow_epoll_wait",
        "allow_epoll",
        "allow_inotify",
        "allow_select",
        "allow_exit",
        "allow_open",
        "allow_stat",
        "allow_access",
        "allow_dup",
        "allow_pipe",
        "allow_chmod",
        "allow_chown",
        "allow_read",
        "allow_write",
        "allow_readdir",
        "allow_readlink",
        "allow_link",
        "allow_symlink",
        "allow_mkdir",
        "allow_utime",
        "allow_fork",
        "allow_wait",
        "allow_alarm",
        "allow_posix_timers",
        "allow_handle_signals",
        "allow_time",
        "allow_sleep",
        "allow_get_ids",
        "allow_get_pids",
        "allow_get_pgids",
        "allow_setrlimit",
        "allow_unlink",
        "allow_poll",
        "allow_rename",
        "allow_eventfd",
        "allow_mmap",
        "allow_mprotect",
        "allow_mlock",
        "allow_safe_bpf",
        "allow_safe_fcntl",
        "allow_tcgets",
        "allow_getrlimit",
        "allow_getrandom",
        "allow_wipe_on_fork",
        "allow_prctl_set_name",
        "allow_prctl_set_vma",
        "allow_futex_wait",
        "allow_futex_wake",
        "allow_futex_wait_bitset",
        "allow_limited_madvise",
        "allow_madvise_populate",
        "allow_mmap_without_exec",
        "allow_mprotect_without_exec",
        "allow_shared_memory",
        "allow_system_malloc",
        "allow_scudo_malloc",
        "allow_restartable_sequences_fast",
        "allow_restartable_sequences_slow",
        "allow_tcmalloc",
        "allow_llvm_sanitizers",
        "allow_llvm_coverage",
        "allow_log_forwarding",
        "allow_static_startup",
        "allow_dynamic_startup",
        "allow_default_policy",
    ];

    if cfg!(target_arch = "x86_64") {
        names.push("allow_pkey_mprotect");
        names.push("allow_pkey_mprotect_without_exec");
    }

    for name in names {
        let policy = format!("USE {name} DEFAULT KILL");
        kafel::compile_with_options(&policy, &builtin_options())
            .unwrap_or_else(|err| panic!("{name} failed to compile: {err}"));
    }
}

#[test]
fn removed_builtin_names_fail() {
    for name in [
        "allow_stdio",
        "allow_malloc",
        "allow_thread",
        "allow_net_client",
    ] {
        let policy = format!("USE {name} DEFAULT KILL");
        let err = kafel::compile_with_options(&policy, &builtin_options()).unwrap_err();
        match err {
            Error::UndefinedPolicy { name: missing, .. } => assert_eq!(missing, name),
            other => panic!("expected undefined policy for {name}, got {other:?}"),
        }
    }
}
