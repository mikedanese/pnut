//! Basic compilation, error display, API surface, and BPF structural invariants.

// ---------------------------------------------------------------------------
// Basic compile
// ---------------------------------------------------------------------------

#[test]
fn simple_compile() {
    let prog = kafel::compile("POLICY p { ALLOW { read, write } } USE p DEFAULT KILL").unwrap();
    assert!(!prog.instructions().is_empty());
}

#[test]
fn backward_compat_compile() {
    let prog = kafel::compile(
        "POLICY p { KILL { ptrace } ALLOW { read, write, close } } USE p DEFAULT ALLOW",
    )
    .unwrap();
    assert!(!prog.instructions().is_empty());
}

#[test]
fn default_options() {
    let prog = kafel::compile_with_options(
        "POLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &kafel::CompileOptions::default(),
    )
    .unwrap();
    assert!(!prog.instructions().is_empty());
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn error_impls_display_and_error() {
    let err = kafel::Error::Parse {
        message: "test".to_string(),
        span: None,
    };
    // Display and Error traits are implemented
    let msg = format!("{err}");
    assert!(!msg.is_empty());
    let _: &dyn std::error::Error = &err;
}

#[test]
fn invalid_input_returns_parse_error() {
    let result = kafel::compile("THIS IS NOT VALID POLICY TEXT @@@ !!!");
    assert!(
        matches!(result, Err(kafel::Error::Parse { .. })),
        "invalid input should produce Parse error"
    );
}

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

#[test]
fn public_api_types() {
    let _: fn(&str) -> Result<kafel::BpfProgram, kafel::Error> = kafel::compile;
    let _: fn(&str, &kafel::CompileOptions) -> Result<kafel::BpfProgram, kafel::Error> =
        kafel::compile_with_options;
    let _opts = kafel::CompileOptions::new();
    let _: fn(&kafel::BpfProgram) -> Result<(), std::io::Error> = kafel::install_filter;

    let _e = kafel::Error::IncludeDepthExceeded;
    let _e = kafel::Error::CircularInclude {
        filename: "test".to_string(),
        span: None,
    };
    let _e = kafel::Error::IncludeNotFound {
        filename: "test".to_string(),
        span: None,
    };
}

// ---------------------------------------------------------------------------
// BPF structural invariants
// ---------------------------------------------------------------------------

#[test]
fn all_jump_offsets_valid() {
    const BPF_JMP_JA: u16 = (libc::BPF_JMP | libc::BPF_JA) as u16;

    let policies = [
        "POLICY p { ALLOW { read, write, open, close, stat, fstat, lstat, poll, lseek, mmap } \
            KILL { ptrace } \
            ERRNO(1) { execve } \
            ALLOW { mprotect, munmap, brk, ioctl } \
            ALLOW { write(fd, buf, count) { fd == 1 || fd == 2 } } \
        } USE p DEFAULT KILL",
        "POLICY p { ALLOW { read } } USE p DEFAULT KILL",
        "POLICY p { KILL { ptrace } } USE p DEFAULT ALLOW",
        "POLICY p { ALLOW { write(fd, buf, count) { fd == 1 || fd == 2 } } } USE p DEFAULT KILL",
    ];

    for policy_text in &policies {
        let prog = kafel::compile(policy_text).unwrap();
        let insns = prog.instructions();

        for (i, insn) in insns.iter().enumerate() {
            let is_conditional =
                (insn.code & 0x07) == libc::BPF_JMP as u16 && insn.code != BPF_JMP_JA;

            if is_conditional {
                let jt_target = i + 1 + insn.jt as usize;
                let jf_target = i + 1 + insn.jf as usize;
                assert!(
                    jt_target < insns.len(),
                    "insn {i} jt={} jumps past end (len={})",
                    insn.jt,
                    insns.len()
                );
                assert!(
                    jf_target < insns.len(),
                    "insn {i} jf={} jumps past end (len={})",
                    insn.jf,
                    insns.len()
                );
            }

            if insn.code == BPF_JMP_JA {
                let target = i + 1 + insn.k as usize;
                assert!(
                    target < insns.len(),
                    "BPF_JA at {i} with k={} jumps past end (len={})",
                    insn.k,
                    insns.len()
                );
            }
        }
    }
}
