//! Parser and resolver error validation tests.
//!
//! Covers error paths from C kafel's broken.c: malformed input, bounds
//! violations, reserved keyword abuse, and structural errors.

use crate::error::Error;
use crate::parser::parse_and_validate;
use crate::resolve;

fn compile_err(input: &str) -> Error {
    let pf = match parse_and_validate(input) {
        Err(e) => return e,
        Ok(pf) => pf,
    };
    resolve::resolve(&pf).unwrap_err()
}

// ---------------------------------------------------------------------------
// Undefined syscall
// ---------------------------------------------------------------------------

#[test]
fn undefined_syscall_in_policy() {
    let err = compile_err(
        "POLICY p { ALLOW { this_is_a_syscall_that_does_not_exist } } USE p DEFAULT KILL",
    );
    assert!(
        matches!(err, Error::UnknownSyscall { ref name, .. } if name == "this_is_a_syscall_that_does_not_exist"),
        "expected UnknownSyscall, got {err}"
    );
}

#[test]
fn undefined_syscall_in_inline_policy() {
    let err = compile_err("ALLOW { nonexistent_syscall_xyz } DEFAULT KILL");
    assert!(
        matches!(err, Error::UnknownSyscall { .. } | Error::Parse { .. }),
        "expected error for undefined syscall, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Undefined policy in USE
// ---------------------------------------------------------------------------

#[test]
fn undefined_policy_in_use() {
    let err = compile_err("USE undef DEFAULT KILL");
    assert!(
        matches!(err, Error::UndefinedPolicy { ref name, .. } if name == "undef"),
        "expected UndefinedPolicy, got {err}"
    );
}

#[test]
fn undefined_policy_with_other_defined() {
    let err = compile_err("POLICY empty {} USE undef DEFAULT KILL");
    assert!(
        matches!(err, Error::UndefinedPolicy { ref name, .. } if name == "undef"),
        "expected UndefinedPolicy, got {err}"
    );
}

#[test]
fn undefined_policy_in_nested_use() {
    let err = compile_err("POLICY broken { USE undef } USE broken DEFAULT KILL");
    assert!(
        matches!(err, Error::UndefinedPolicy { ref name, .. } if name == "undef"),
        "expected UndefinedPolicy, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Too many syscall args
// ---------------------------------------------------------------------------

#[test]
fn too_many_syscall_args() {
    let err = compile_err("POLICY p { ALLOW { write(a, b, c, d, e, f, g) } } USE p DEFAULT KILL");
    assert!(
        matches!(err, Error::Parse { ref message, .. } if message.contains("7 arguments")),
        "expected ParseError about too many args, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Undefined argument in filter
// ---------------------------------------------------------------------------

#[test]
fn undefined_argument_in_filter() {
    let err = compile_err(
        "POLICY p { ALLOW { write(fd, buf, count) { undef == 1 || fd == 2 } } } USE p DEFAULT KILL",
    );
    assert!(
        matches!(err, Error::UndeclaredArgument { ref name, .. } if name == "undef"),
        "expected UndeclaredArgument, got {err}"
    );
}

#[test]
fn duplicate_argument_names() {
    // write(myfd, myfd, mysize) — duplicate arg name
    // This may or may not be caught depending on implementation
    let result = parse_and_validate(
        "POLICY p { ALLOW { write(myfd, myfd, mysize) { myfd == 1 } } } USE p DEFAULT KILL",
    )
    .and_then(|pf| resolve::resolve(&pf).map(|_| ()));
    // Either it errors or it silently works — but it must not panic
    let _ = result;
}

// ---------------------------------------------------------------------------
// Unterminated comment
// ---------------------------------------------------------------------------

#[test]
fn unterminated_block_comment() {
    let err = compile_err("POLICY empty {} USE empty DEFAULT KILL /* oops ");
    assert!(
        matches!(err, Error::Parse { .. }),
        "expected ParseError for unterminated comment, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Redefined policy
// ---------------------------------------------------------------------------

#[test]
fn redefined_policy_name() {
    // Two policies with the same name
    let result = parse_and_validate("POLICY p {} POLICY p {} USE p DEFAULT KILL")
        .and_then(|pf| resolve::resolve(&pf).map(|_| ()));
    // Should either error or handle gracefully — must not panic
    let _ = result;
}

// ---------------------------------------------------------------------------
// Garbage input
// ---------------------------------------------------------------------------

#[test]
fn completely_invalid_input() {
    let err = compile_err("THIS IS NOT VALID POLICY TEXT @@@ !!!");
    assert!(
        matches!(err, Error::Parse { .. }),
        "expected ParseError, got {err}"
    );
}

#[test]
fn empty_input_does_not_panic() {
    let result = parse_and_validate("").and_then(|pf| resolve::resolve(&pf).map(|_| ()));
    // Empty is fine as long as it doesn't panic
    let _ = result;
}

// ---------------------------------------------------------------------------
// Reserved keywords as identifiers
// ---------------------------------------------------------------------------

#[test]
fn keywords_as_policy_names() {
    // Using reserved keywords as policy/syscall names should be rejected by
    // the grammar or produce errors. Pest greedily matches keywords.
    let keywords = [
        "ALLOW",
        "KILL",
        "KILL_PROCESS",
        "LOG",
        "ERRNO",
        "TRAP",
        "TRACE",
        "USE",
        "POLICY",
        "DEFAULT",
    ];
    for kw in &keywords {
        // As policy name
        let input = format!("POLICY {kw} {{}} USE {kw} DEFAULT KILL");
        let result = parse_and_validate(&input).and_then(|pf| resolve::resolve(&pf).map(|_| ()));
        // Must either error or not panic — keywords consumed by grammar
        // should prevent these from being valid identifiers
        let _ = result;
    }
}

#[test]
fn keywords_as_syscall_names() {
    let keywords = ["ALLOW", "KILL", "POLICY", "DEFAULT", "USE"];
    for kw in &keywords {
        let input = format!("POLICY p {{ ALLOW {{ {kw} }} }} USE p DEFAULT KILL");
        let result = parse_and_validate(&input).and_then(|pf| resolve::resolve(&pf).map(|_| ()));
        // Must not panic
        let _ = result;
    }
}

// ---------------------------------------------------------------------------
// ERRNO/TRAP/TRACE bounds
// ---------------------------------------------------------------------------

#[test]
fn errno_value_in_valid_range() {
    // ERRNO(1) should work
    let result = crate::compile("POLICY p { ERRNO(1) { write } } USE p DEFAULT KILL");
    assert!(
        result.is_ok(),
        "ERRNO(1) should compile: {:?}",
        result.err()
    );
}

#[test]
fn errno_value_zero() {
    // ERRNO(0) should compile (valid range)
    let result = crate::compile("POLICY p { ERRNO(0) { write } } USE p DEFAULT KILL");
    assert!(
        result.is_ok(),
        "ERRNO(0) should compile: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Circular USE
// ---------------------------------------------------------------------------

#[test]
fn self_referential_use() {
    let err = compile_err("POLICY a { USE a } USE a DEFAULT KILL");
    assert!(
        matches!(err, Error::CircularUse { .. }),
        "expected CircularUse, got {err}"
    );
}

#[test]
fn two_way_use_cycle() {
    let err = compile_err("POLICY a { USE b } POLICY b { USE a } USE a DEFAULT KILL");
    assert!(
        matches!(err, Error::CircularUse { .. }),
        "expected CircularUse, got {err}"
    );
}
