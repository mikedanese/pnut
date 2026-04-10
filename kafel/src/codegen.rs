//! BPF code generation for seccomp policies.
//!
//! This module converts a resolved policy (flat list of syscall rules with
//! numeric syscall numbers and actions) into a BPF program (`Vec<sock_filter>`)
//! ready for `seccomp(SECCOMP_SET_MODE_FILTER)`.
//!
//! The codegen pipeline follows kafel C's architecture:
//! 1. Range normalization: merge adjacent same-action unconditional syscalls
//!    into contiguous ranges, fill gaps with the default action
//! 2. Binary decision tree: build a balanced BPF_JGE search tree over ranges
//! 3. Reverse emission: emit instructions backwards so all jump targets are
//!    known at emission time; reverse the buffer at the end
//! 4. Action caching: deduplicate BPF_RET instructions for identical actions
//! 5. Trampoline insertion: BPF_JA bridges for jumps > 255 instructions

mod expr;
mod ranges;
mod reverse;

use reverse::ReverseCodegen;

use crate::error::Error;
use crate::resolve::Action;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AUDIT_ARCH_X86_64` — not exported by libc, defined per the kernel header
/// `<linux/audit.h>`. Value is `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// Offset of `seccomp_data.arch` in the seccomp BPF data block.
const OFFSET_ARCH: u32 = 4;

/// Offset of `seccomp_data.nr` (syscall number) in the seccomp BPF data block.
const OFFSET_NR: u32 = 0;

/// Base offset of `seccomp_data.args[]` — each arg is 8 bytes (u64).
/// Little-endian: low 32-bit word at base, high 32-bit word at base+4.
const OFFSET_ARGS: u32 = 16;

// BPF instruction codes (composed from libc constants for clarity).
const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const BPF_JMP_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const BPF_JMP_JGT_K: u16 = (libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K) as u16;
const BPF_JMP_JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
const BPF_JMP_JSET_K: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
const BPF_ALU_AND_K: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
const BPF_JMP_JA: u16 = (libc::BPF_JMP | libc::BPF_JA) as u16;
const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// Maximum BPF conditional jump offset (8-bit field).
const MAX_JUMP: i32 = 255;

/// Maximum syscall number we cover. Matches kafel C's MAX_SYSCALL_NR.
/// Using a large value to cover the full syscall number space.
const MAX_SYSCALL_NR: u32 = 0x3FF; // 1023, same as kafel C

/// Context passed to include resolvers, describing where the `#include` occurs.
pub struct IncludeContext<'a> {
    /// Path or name of the file containing the `#include` directive,
    /// or `None` for includes at the top level.
    pub parent: Option<&'a str>,
}

/// Result returned by an include resolver.
pub struct IncludeResult {
    /// The resolved file's contents.
    pub contents: String,
    /// The canonical path/name of the resolved file. If set, this is used as
    /// the `parent` context for any nested `#include` directives and for
    /// circular-include detection. If `None`, the raw include filename is used.
    pub canonical_name: Option<String>,
}

impl From<String> for IncludeResult {
    fn from(contents: String) -> Self {
        Self {
            contents,
            canonical_name: None,
        }
    }
}

type IncludeResolver = dyn Fn(&str, &IncludeContext) -> Result<IncludeResult, Error>;

// ---------------------------------------------------------------------------
// BpfProgram
// ---------------------------------------------------------------------------

/// A compiled BPF program ready for loading via `seccomp(SECCOMP_SET_MODE_FILTER)`.
///
/// Contains the raw `sock_filter` instruction sequence produced by
/// [`compile()`] or [`compile_with_options()`]. Use [`instructions()`](Self::instructions)
/// to access the slice, and [`install_filter()`] to load it into the current
/// process.
///
/// The `Debug` implementation prints a disassembly of the BPF instructions,
/// useful for debugging policy behavior.
pub struct BpfProgram {
    insns: Vec<libc::sock_filter>,
}

impl BpfProgram {
    /// Returns the raw BPF instruction slice.
    pub fn instructions(&self) -> &[libc::sock_filter] {
        &self.insns
    }

    /// Returns the number of BPF instructions.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Returns true if the program has no instructions.
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }
}

impl std::fmt::Debug for BpfProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "BpfProgram ({} instructions):", self.insns.len())?;
        for (i, insn) in self.insns.iter().enumerate() {
            writeln!(
                f,
                "  {:3}: code=0x{:04x} jt={} jf={} k=0x{:08x}",
                i, insn.code, insn.jt, insn.jf, insn.k
            )?;
        }
        Ok(())
    }
}

impl std::fmt::Display for BpfProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "BPF program: {} instructions", self.insns.len())?;
        for (i, insn) in self.insns.iter().enumerate() {
            let code_class = insn.code & 0x07;
            let desc = match code_class {
                0x00 => "ld",  // BPF_LD
                0x04 => "alu", // BPF_ALU
                0x05 => "jmp", // BPF_JMP
                0x06 => "ret", // BPF_RET
                _ => "???",
            };
            writeln!(
                f,
                "  {:3}: {:3} code=0x{:04x} jt={} jf={} k=0x{:08x}",
                i, desc, insn.code, insn.jt, insn.jf, insn.k
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CompileOptions
// ---------------------------------------------------------------------------

/// Options controlling policy compilation.
///
/// Use builder methods to configure include resolution, preludes, and depth
/// limits. The default configuration has no include resolver, no prelude,
/// and a maximum include depth of 10.
///
/// # Example
///
/// ```rust,no_run
/// use kafel::CompileOptions;
///
/// let options = CompileOptions::new()
///     .with_prelude("#define STDOUT 1")
///     .with_max_depth(5);
/// ```
pub struct CompileOptions {
    /// Callback to resolve `#include "filename"` directives.
    ///
    /// The callback receives the filename string from the directive and
    /// returns either the policy text content or a `Error`.
    /// If `None`, any `#include` directive will produce an error.
    pub(crate) include_resolver: Option<Box<IncludeResolver>>,
    /// Policy text logically prepended to the input before compilation.
    ///
    /// Defines and policies from the prelude are available to the main
    /// policy. No file I/O — the prelude is supplied as a string.
    pub(crate) prelude: Option<String>,
    /// Maximum depth for recursive `#include` resolution (default 10).
    pub(crate) max_include_depth: usize,
}

impl Default for CompileOptions {
    fn default() -> Self {
        CompileOptions {
            include_resolver: None,
            prelude: None,
            max_include_depth: 10,
        }
    }
}

impl std::fmt::Debug for CompileOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompileOptions")
            .field(
                "include_resolver",
                &if self.include_resolver.is_some() {
                    "Some(<fn>)"
                } else {
                    "None"
                },
            )
            .field("prelude", &self.prelude)
            .field("max_include_depth", &self.max_include_depth)
            .finish()
    }
}

impl CompileOptions {
    /// Create a new `CompileOptions` with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prelude — policy text logically prepended to the input.
    ///
    /// Defines and policies declared in the prelude are available to the
    /// main policy text. This is useful for shared constants or common
    /// policy fragments.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use kafel::CompileOptions;
    ///
    /// let opts = CompileOptions::new()
    ///     .with_prelude("#define STDOUT 1\n#define STDERR 2");
    /// ```
    pub fn with_prelude(mut self, prelude: impl Into<String>) -> Self {
        self.prelude = Some(prelude.into());
        self
    }

    /// Set the include resolver callback.
    ///
    /// The callback receives the filename from `#include "filename"` and
    /// returns the file's policy text content or an error. The core crate
    /// performs no file I/O — the caller is responsible for locating and
    /// reading include files.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use kafel::{Error, CompileOptions};
    /// use std::collections::HashMap;
    ///
    /// let mut libs = HashMap::new();
    /// libs.insert("stdio.policy".to_string(),
    ///     "POLICY stdio { ALLOW { read, write, close } }".to_string());
    ///
    /// let opts = CompileOptions::new()
    ///     .with_include_resolver(move |name, _ctx| {
    ///         libs.get(name)
    ///             .cloned()
    ///             .map(Into::into)
    ///             .ok_or_else(|| Error::IncludeNotFound {
    ///                 filename: name.to_string(),
    ///                 span: None,
    ///             })
    ///     });
    /// ```
    pub fn with_include_resolver<F>(mut self, resolver: F) -> Self
    where
        F: Fn(&str, &IncludeContext) -> Result<IncludeResult, Error> + 'static,
    {
        self.include_resolver = Some(Box::new(resolver));
        self
    }

    /// Set the maximum include depth (default 10).
    ///
    /// If recursive `#include` directives exceed this depth, compilation
    /// fails with `Error::IncludeDepthExceeded`.
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_include_depth = max_depth;
        self
    }
}

// ---------------------------------------------------------------------------
// Action mapping
// ---------------------------------------------------------------------------

/// Map a resolved action to its `SECCOMP_RET_*` value.
fn action_to_ret(action: &Action) -> u32 {
    match action {
        Action::Allow => libc::SECCOMP_RET_ALLOW,
        Action::Kill => libc::SECCOMP_RET_KILL,
        Action::KillProcess => libc::SECCOMP_RET_KILL_PROCESS,
        Action::Log => libc::SECCOMP_RET_LOG,
        Action::UserNotif => {
            // SECCOMP_RET_USER_NOTIF = 0x7FC00000
            0x7FC0_0000
        }
        Action::Errno(n) => libc::SECCOMP_RET_ERRNO | (*n & 0xFFFF),
        Action::Trap(n) => libc::SECCOMP_RET_TRAP | (*n & 0xFFFF),
        Action::Trace(n) => libc::SECCOMP_RET_TRACE | (*n & 0xFFFF),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compile a Kafel policy string into a BPF program.
///
/// This is the primary entry point. It parses the policy, resolves names
/// and constants, and generates BPF bytecode.
///
/// # Example
///
/// ```rust,no_run
/// let program = kafel::compile(
///     "POLICY p { ALLOW { read, write, close } } USE p DEFAULT KILL"
/// ).unwrap();
/// assert!(!program.instructions().is_empty());
/// ```
///
/// # Errors
///
/// Returns [`Error`] on parse errors, unknown syscalls, undefined
/// identifiers, circular USE references, or codegen failures.
pub fn compile(policy_text: &str) -> Result<BpfProgram, Error> {
    compile_with_options(policy_text, &CompileOptions::default())
}

/// Compile a Kafel policy string with options.
///
/// Like [`compile()`] but accepts [`CompileOptions`] for controlling
/// compilation behavior including include resolution, preludes, and
/// depth limits.
///
/// # Example
///
/// ```rust,no_run
/// use kafel::{compile_with_options, CompileOptions};
///
/// let opts = CompileOptions::new()
///     .with_prelude("#define STDOUT 1");
///
/// let program = compile_with_options(
///     "POLICY p { ALLOW { write(fd, buf, count) { fd == STDOUT } } } USE p DEFAULT KILL",
///     &opts,
/// ).unwrap();
/// ```
///
/// # Errors
///
/// Returns [`Error`] on parse errors, include resolution failures,
/// unknown syscalls, undefined identifiers, circular USE/include references,
/// or codegen failures.
pub fn compile_with_options(
    policy_text: &str,
    options: &CompileOptions,
) -> Result<BpfProgram, Error> {
    let policy = parse_policy(policy_text, options)?;
    policy.codegen()
}

/// Parse and resolve a policy string into a [`Policy`](crate::resolve::Policy),
/// stopping before BPF codegen.
///
/// This allows callers to programmatically inspect or mutate the resolved
/// policy (e.g., adding extra rules) before generating BPF bytecode via
/// [`Policy::codegen()`](crate::resolve::Policy::codegen).
pub fn parse_policy(
    policy_text: &str,
    options: &CompileOptions,
) -> Result<crate::resolve::Policy, Error> {
    use std::collections::HashSet;

    let mut policy_file =
        crate::parser::parse_with_includes(policy_text, options, &mut HashSet::new(), 0, None)?;

    if let Some(ref prelude_text) = options.prelude {
        let prelude_pf = crate::parser::parse_with_includes(
            prelude_text,
            options,
            &mut HashSet::new(),
            0,
            None,
        )?;
        let mut merged_defines = prelude_pf.defines;
        merged_defines.extend(policy_file.defines);
        policy_file.defines = merged_defines;

        let mut merged_policies = prelude_pf.policies;
        merged_policies.extend(policy_file.policies);
        policy_file.policies = merged_policies;

        if policy_file.use_stmt.is_none() {
            policy_file.use_stmt = prelude_pf.use_stmt;
        }
    }

    crate::parser::validate(&policy_file)?;
    crate::resolve::resolve(&policy_file)
}

/// Generate BPF bytecode from a resolved policy (crate-internal).
pub(crate) fn codegen_policy(policy: &crate::resolve::Policy) -> Result<BpfProgram, Error> {
    let mut codegen = ReverseCodegen::new();
    let insns = codegen.generate(policy)?;
    Ok(BpfProgram { insns })
}

// ---------------------------------------------------------------------------
// Filter loading
// ---------------------------------------------------------------------------

/// Install a compiled BPF filter into the current process.
///
/// Loads the filter via `seccomp(SECCOMP_SET_MODE_FILTER, 0, prog)`.
///
/// # Prerequisites
///
/// The caller must set `PR_SET_NO_NEW_PRIVS` before calling this function
/// when running without `CAP_SYS_ADMIN`. Without it, `seccomp()` will return
/// `EACCES`. pnut (and any other unprivileged caller) should set this
/// unconditionally before loading a filter.
///
/// # Safety
///
/// After this call, the process (and all future children) will be constrained
/// by the filter. Ensure the filter allows all syscalls needed for normal
/// operation (including `exit_group` for clean termination).
///
/// # Errors
///
/// Returns an `io::Error` if `seccomp()` fails.
pub fn install_filter(program: &BpfProgram) -> Result<(), std::io::Error> {
    let prog = libc::sock_fprog {
        len: program.insns.len() as u16,
        filter: program.insns.as_ptr() as *mut libc::sock_filter,
    };

    // Install the filter via seccomp(2)
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
            libc::SECCOMP_FILTER_FLAG_TSYNC as libc::c_ulong,
            &prog as *const libc::sock_fprog as libc::c_ulong,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_check_is_first_two_instructions() {
        let prog = compile("POLICY p { KILL { ptrace } } USE p DEFAULT ALLOW").unwrap();
        let insns = prog.instructions();

        // Instruction 0: load seccomp_data.arch (offset 4)
        assert_eq!(insns[0].code, BPF_LD_W_ABS);
        assert_eq!(insns[0].k, OFFSET_ARCH);

        // Instruction 1: jeq AUDIT_ARCH_X86_64
        assert_eq!(insns[1].code, BPF_JMP_JEQ_K);
        assert_eq!(insns[1].k, AUDIT_ARCH_X86_64);
        // jt=1 (skip kill, continue), jf=0 (fall through to kill)
        assert_eq!(insns[1].jt, 1);
        assert_eq!(insns[1].jf, 0);

        // Instruction 2: ret KILL_PROCESS (arch mismatch)
        assert_eq!(insns[2].code, BPF_RET_K);
        assert_eq!(insns[2].k, libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn syscall_load_follows_arch_check() {
        let prog = compile("POLICY p { KILL { ptrace } } USE p DEFAULT ALLOW").unwrap();
        let insns = prog.instructions();

        // Instruction 3: load seccomp_data.nr (offset 0)
        assert_eq!(insns[3].code, BPF_LD_W_ABS);
        assert_eq!(insns[3].k, OFFSET_NR);
    }

    #[test]
    fn kill_ptrace_allow_default() {
        let prog = compile("POLICY p { KILL { ptrace } } USE p DEFAULT ALLOW").unwrap();
        let insns = prog.instructions();

        assert!(
            insns.len() < 10,
            "optimized program should be compact, got {}",
            insns.len()
        );

        let has_kill = insns
            .iter()
            .any(|i| i.code == BPF_RET_K && i.k == libc::SECCOMP_RET_KILL);
        let has_allow = insns
            .iter()
            .any(|i| i.code == BPF_RET_K && i.k == libc::SECCOMP_RET_ALLOW);
        assert!(has_kill, "should have KILL return");
        assert!(has_allow, "should have ALLOW return");

        let jge_count = insns.iter().filter(|i| i.code == BPF_JMP_JGE_K).count();
        assert!(jge_count >= 1, "should use JGE for decision tree");
    }

    #[test]
    fn allow_three_syscalls_default_kill() {
        let prog = compile("POLICY p { ALLOW { read, write, close } } USE p DEFAULT KILL").unwrap();
        let insns = prog.instructions();

        assert!(
            insns.len() < 11,
            "optimized should be fewer than 11, got {}",
            insns.len()
        );

        let has_allow = insns
            .iter()
            .any(|i| i.code == BPF_RET_K && i.k == libc::SECCOMP_RET_ALLOW);
        let has_kill = insns
            .iter()
            .any(|i| i.code == BPF_RET_K && i.k == libc::SECCOMP_RET_KILL);
        assert!(has_allow, "should have ALLOW return");
        assert!(has_kill, "should have KILL return");
    }

    #[test]
    fn errno_action_encoding() {
        let prog = compile("POLICY p { ERRNO(1) { execve } } USE p DEFAULT ALLOW").unwrap();
        let insns = prog.instructions();

        let has_errno = insns
            .iter()
            .any(|i| i.code == BPF_RET_K && i.k == (libc::SECCOMP_RET_ERRNO | 1));
        assert!(has_errno, "should have ERRNO(1) return instruction");
    }

    #[test]
    fn empty_policy_default_kill() {
        let prog = compile("POLICY p {} USE p DEFAULT KILL").unwrap();
        let insns = prog.instructions();

        assert_eq!(insns.len(), 5);
        assert_eq!(insns[4].code, BPF_RET_K);
        assert_eq!(insns[4].k, libc::SECCOMP_RET_KILL);
    }

    #[test]
    fn program_debug_format() {
        let prog = compile("POLICY p {} USE p DEFAULT KILL").unwrap();
        let debug = format!("{:?}", prog);
        assert!(debug.contains("BpfProgram"));
        assert!(debug.contains("instructions"));
    }

    #[test]
    fn conditional_rule_compiles() {
        let prog =
            compile("POLICY p { ALLOW { write(fd, buf, count) { fd == 1 } } } USE p DEFAULT KILL")
                .unwrap();
        let insns = prog.instructions();
        assert!(
            insns.len() > 5,
            "conditional rule should generate expression code, got {} insns",
            insns.len()
        );
    }

    #[test]
    fn conditional_rule_has_arg_load() {
        let prog =
            compile("POLICY p { ALLOW { write(fd, buf, count) { fd == 1 } } } USE p DEFAULT KILL")
                .unwrap();
        let insns = prog.instructions();

        let has_arg_load = insns.iter().any(|i| i.code == BPF_LD_W_ABS && i.k == 16);
        assert!(has_arg_load, "should load arg0 (offset 16)");
    }

    #[test]
    fn jset_optimization_for_masked_eq_zero() {
        let prog = compile(
            "POLICY p { ALLOW { mmap(addr, len, prot, flags, fd, offset) { (prot & 0x4) == 0 } } } USE p DEFAULT KILL",
        )
        .unwrap();
        let insns = prog.instructions();

        let has_jset = insns.iter().any(|i| i.code == BPF_JMP_JSET_K);
        assert!(has_jset, "masked eq zero should use BPF_JSET");

        let has_and = insns.iter().any(|i| i.code == BPF_ALU_AND_K);
        assert!(
            !has_and,
            "masked eq zero should not use BPF_AND, should use BPF_JSET"
        );
    }

    #[test]
    fn sixty_four_bit_generates_high_low_checks() {
        let prog = compile(
            "POLICY p { ALLOW { write(fd, buf, count) { fd == 0x100000001 } } } USE p DEFAULT KILL",
        )
        .unwrap();
        let insns = prog.instructions();

        let has_high = insns.iter().any(|i| i.code == BPF_LD_W_ABS && i.k == 20);
        let has_low = insns.iter().any(|i| i.code == BPF_LD_W_ABS && i.k == 16);
        assert!(has_high, "should load arg0 high word (offset 20)");
        assert!(has_low, "should load arg0 low word (offset 16)");

        let jeq_1_count = insns
            .iter()
            .filter(|i| i.code == BPF_JMP_JEQ_K && i.k == 1)
            .count();
        assert!(
            jeq_1_count >= 2,
            "should have JEQ against 1 for both high and low words, got {jeq_1_count}"
        );
    }

    #[test]
    fn mixed_unconditional_and_conditional() {
        let prog = compile(
            "POLICY p { KILL { ptrace } ALLOW { write(fd, buf, count) { fd == 1 } } } USE p DEFAULT KILL",
        )
        .unwrap();
        let insns = prog.instructions();

        assert!(
            insns.len() > 5,
            "should have decision tree + expression code"
        );

        let has_kill = insns
            .iter()
            .any(|i| i.code == BPF_RET_K && i.k == libc::SECCOMP_RET_KILL);
        let has_allow = insns
            .iter()
            .any(|i| i.code == BPF_RET_K && i.k == libc::SECCOMP_RET_ALLOW);
        assert!(has_kill, "should have KILL return");
        assert!(has_allow, "should have ALLOW return");

        let has_arg_load = insns.iter().any(|i| i.code == BPF_LD_W_ABS && i.k == 16);
        assert!(has_arg_load, "should load arg0 for write filter");
    }
}
