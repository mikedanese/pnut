//! End-to-end tests for rendered kafel diagnostics.
//!
//! When a seccomp policy has a semantic error (unknown syscall, undefined
//! identifier, undeclared argument, undefined policy in USE, ...), pnut
//! should surface a multi-line diagnostic with a `--> file:line:col` header
//! and a rendered source snippet with a caret, not just a one-line message.
//!
//! These tests feed deliberately broken policies through the CLI and assert
//! on the shape of the stderr output.

use std::process::Command;

fn pnut() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pnut"))
}

/// Minimal config with a seccomp policy file and the bare minimum needed
/// for pnut to get far enough to compile the policy.
fn config_with_policy_file(policy_path: &str) -> String {
    format!(
        r#"seccomp_policy_file = "{policy_path}"

[uid_map]
inside = 0
outside = 1000
count = 1

[gid_map]
inside = 0
outside = 1000
count = 1
"#
    )
}

fn config_with_inline_policy(policy: &str) -> String {
    format!(
        r#"seccomp_policy = '''
{policy}'''

[uid_map]
inside = 0
outside = 1000
count = 1

[gid_map]
inside = 0
outside = 1000
count = 1
"#
    )
}

fn run_with_config(config: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("pnut.toml");
    std::fs::write(&config_path, config).unwrap();
    let out = pnut()
        .arg("--config")
        .arg(&config_path)
        .arg("--")
        .arg("/bin/true")
        .output()
        .expect("failed to run pnut");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Write a policy file and return its path. Kept on disk for the duration
/// of the test.
fn write_policy(name: &str, contents: &str) -> String {
    let _ = std::fs::create_dir_all("/tmp/claude");
    let path = format!(
        "/tmp/claude/pnut-diag-{}-{}.kafel",
        name,
        std::process::id()
    );
    std::fs::write(&path, contents).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Unknown syscall
// ---------------------------------------------------------------------------

#[test]
fn unknown_syscall_renders_snippet_with_file_path() {
    let policy = "POLICY p {\n    ALLOW { read, writee, close }\n}\nUSE p DEFAULT KILL\n";
    let path = write_policy("unknown_syscall", policy);
    let stderr = run_with_config(&config_with_policy_file(&path));

    assert!(
        stderr.contains("unknown syscall: 'writee'"),
        "stderr = {stderr}"
    );
    assert!(
        stderr.contains(&format!("--> {path}:2:")),
        "expected file:line header referencing policy path, stderr = {stderr}"
    );
    assert!(
        stderr.contains("2 |     ALLOW { read, writee, close }"),
        "expected rendered source line, stderr = {stderr}"
    );
    assert!(
        stderr.contains("^^^^^^"),
        "expected caret line under 'writee', stderr = {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Undeclared argument
// ---------------------------------------------------------------------------

#[test]
fn undeclared_argument_renders_snippet() {
    let policy = "POLICY p {\n    ALLOW {\n        write(fd, buf, count) { flags == 1 }\n    }\n}\nUSE p DEFAULT KILL\n";
    let path = write_policy("undeclared_arg", policy);
    let stderr = run_with_config(&config_with_policy_file(&path));

    assert!(
        stderr.contains("undeclared argument 'flags' in syscall 'write'"),
        "stderr = {stderr}"
    );
    assert!(
        stderr.contains(&format!("--> {path}:3:")),
        "stderr = {stderr}"
    );
    assert!(
        stderr.contains("^^^^^"),
        "expected caret under 'flags', stderr = {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Undefined policy in USE
// ---------------------------------------------------------------------------

#[test]
fn undefined_use_target_renders_snippet() {
    let policy = "POLICY p {\n    ALLOW { read }\n}\nUSE nonexistent DEFAULT KILL\n";
    let path = write_policy("undefined_use", policy);
    let stderr = run_with_config(&config_with_policy_file(&path));

    assert!(
        stderr.contains("USE references undefined policy 'nonexistent'"),
        "stderr = {stderr}"
    );
    assert!(
        stderr.contains(&format!("--> {path}:4:")),
        "stderr = {stderr}"
    );
    assert!(
        stderr.contains("^^^^^^^^^^^"),
        "expected caret under 'nonexistent', stderr = {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Inline policies render with <input> as the filename
// ---------------------------------------------------------------------------

#[test]
fn inline_policy_error_uses_input_placeholder() {
    let policy = "POLICY p {\n    ALLOW { read, writee }\n}\nUSE p DEFAULT KILL\n";
    let stderr = run_with_config(&config_with_inline_policy(policy));

    assert!(
        stderr.contains("unknown syscall: 'writee'"),
        "stderr = {stderr}"
    );
    assert!(
        stderr.contains("--> <input>:"),
        "inline policies should render with <input> as the filename, stderr = {stderr}"
    );
    assert!(stderr.contains("^^^^^^"), "stderr = {stderr}");
}
