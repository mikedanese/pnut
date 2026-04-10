//! Seccomp policy compilation for the sandbox.

use std::path::Path;

use crate::config::{Namespaces, SeccompSource};
use crate::error::BuildError;

pub(crate) fn prepare_program(
    source: Option<&SeccompSource>,
    ns_config: &Namespaces,
) -> std::result::Result<Option<kafel::BpfProgram>, BuildError> {
    let need_userns_block = !ns_config.allow_nested_userns;

    match source {
        Some(SeccompSource::Inline(policy_text)) => {
            compile_policy(policy_text, None, None, need_userns_block)
        }
        Some(SeccompSource::File(policy_path)) => {
            let contents =
                std::fs::read_to_string(policy_path).map_err(|e| BuildError::SeccompFileRead {
                    path: policy_path.display().to_string(),
                    source: e,
                })?;
            let base_dir = policy_path.parent().unwrap_or(Path::new("."));
            let filename = policy_path.display().to_string();
            compile_policy(
                &contents,
                Some(base_dir),
                Some(filename.as_str()),
                need_userns_block,
            )
        }
        None if need_userns_block => {
            // No user policy, but we still need a filter to block nested namespaces.
            let mut policy = kafel::Policy {
                entries: Vec::new(),
                default_action: kafel::Action::Allow,
            };
            inject_userns_deny(&mut policy)?;
            policy
                .codegen()
                .map(Some)
                .map_err(|e| BuildError::SeccompCompile(e.to_string()))
        }
        None => Ok(None),
    }
}

/// Namespace clone flags that must be denied to prevent sandbox escape.
const UNSAFE_NS_FLAGS: u64 = libc::CLONE_NEWNS as u64
    | libc::CLONE_NEWUSER as u64
    | libc::CLONE_NEWNET as u64
    | libc::CLONE_NEWUTS as u64
    | libc::CLONE_NEWCGROUP as u64
    | libc::CLONE_NEWIPC as u64
    | libc::CLONE_NEWPID as u64;

fn compile_policy(
    policy_text: &str,
    base_dir: Option<&Path>,
    filename: Option<&str>,
    block_nested_userns: bool,
) -> std::result::Result<Option<kafel::BpfProgram>, BuildError> {
    let mut options = kafel::CompileOptions::new().with_prelude(kafel::BUILTIN_PRELUDE);

    if let Some(dir) = base_dir {
        let resolver = kafel::FilesystemResolver::new(dir);
        options = options.with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));
    }

    // Render any kafel error with a source snippet so the user sees where
    // in their policy file the problem is, not just a one-line message.
    let render = |e: kafel::Error| -> BuildError {
        BuildError::SeccompCompile(kafel::render_diagnostic(&e, policy_text, filename))
    };

    let mut policy = kafel::parse_policy(policy_text, &options).map_err(render)?;

    // pnut installs the seccomp filter before execve and chdir, so these
    // must always be allowed. Runtime startup syscalls (set_tid_address,
    // mprotect, etc.) are the user's responsibility via allow_static_startup
    // or allow_dynamic_startup in the policy.
    for name in ["execve", "execveat", "chdir"] {
        let nr = kafel::resolve_syscall(name).map_err(render)?;
        policy.add_entry(kafel::PolicyEntry {
            syscall_number: nr,
            action: kafel::Action::Allow,
            filter: None,
        });
    }

    // Block nested namespace creation (matches sandbox2/policy.cc:252-284).
    if block_nested_userns {
        inject_userns_deny(&mut policy)?;
    }

    policy.codegen().map(Some).map_err(render)
}

/// Inject seccomp rules to deny nested namespace creation.
///
/// - `clone3` → ERRNO(ENOSYS): flags are in a kernel-read struct, so we can't
///   filter from seccomp. ENOSYS forces glibc to fall back to `clone`.
/// - `clone` → ERRNO(EPERM) when arg0 has any namespace flag.
/// - `unshare` → ERRNO(EPERM) when arg0 has any namespace flag.
fn inject_userns_deny(policy: &mut kafel::Policy) -> std::result::Result<(), BuildError> {
    let map_err = |e: kafel::Error| BuildError::SeccompCompile(e.to_string());

    // Block clone3 entirely.
    let clone3_nr = kafel::resolve_syscall("clone3").map_err(map_err)?;
    policy.add_entry(kafel::PolicyEntry {
        syscall_number: clone3_nr,
        action: kafel::Action::Errno(libc::ENOSYS as u32),
        filter: None,
    });

    // Block clone/unshare when arg0 has namespace flags.
    // Filter: (arg0 & UNSAFE_NS_FLAGS) != 0 → EPERM
    for name in ["clone", "unshare"] {
        let nr = kafel::resolve_syscall(name).map_err(map_err)?;
        policy.add_entry(kafel::PolicyEntry {
            syscall_number: nr,
            action: kafel::Action::Errno(libc::EPERM as u32),
            filter: Some(kafel::Expr::MaskedCompare {
                arg_index: 0,
                mask: Box::new(kafel::Expr::Constant(UNSAFE_NS_FLAGS)),
                op: kafel::CmpOp::Ne,
                rhs: Box::new(kafel::Expr::Constant(0)),
            }),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_inline_policy_with_typed_api() {
        let policy_text = "POLICY p { ALLOW { read, write } }\nUSE p DEFAULT KILL\n";
        let result = compile_policy(policy_text, None, None, false);
        assert!(result.is_ok(), "compile_policy failed: {result:?}");
        assert!(result.unwrap().is_some());
    }
}
