//! Tests for parser cleanup and name resolution.
//!
//! These tests probe edge cases the Generator's own tests may not cover.

use crate::error::Error;
use crate::parser::parse_and_validate;
use crate::resolve::{self, Expr, Policy};

/// Helper: parse and resolve a policy string.
fn parse_and_resolve(input: &str) -> Result<Policy, Error> {
    let pf = parse_and_validate(input)?;
    resolve::resolve(&pf)
}

// ---------------------------------------------------------------------------
// 11.1: No forbidden dependencies (verified by build, not a test)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 11.3: Define substitution
// ---------------------------------------------------------------------------

#[test]
fn adversarial_define_transitive_resolution() {
    // A defines B, B defines C -- transitive chain should resolve.
    let input = r#"
        #define A 10
        #define B A

        POLICY test {
            ALLOW {
                write(fd, buf, count) { fd == B }
            }
        }
        USE test DEFAULT KILL
    "#;
    let resolved = parse_and_resolve(input).unwrap();
    let filter = resolved.entries[0].filter.as_ref().unwrap();
    match filter {
        Expr::Compare(_, _, rhs) => {
            assert!(
                matches!(rhs.as_ref(), Expr::Constant(10)),
                "B should resolve through A to 10, got {rhs:?}"
            );
        }
        other => panic!("expected Compare, got {other:?}"),
    }
}

#[test]
fn adversarial_define_bitor_resolution() {
    // Define with bitwise OR of other defines.
    let input = r#"
        #define FLAG_A 0x1
        #define FLAG_B 0x2
        #define BOTH FLAG_A|FLAG_B

        POLICY test {
            ALLOW {
                write(fd, buf, count) { fd == BOTH }
            }
        }
        USE test DEFAULT KILL
    "#;
    let resolved = parse_and_resolve(input).unwrap();
    let filter = resolved.entries[0].filter.as_ref().unwrap();
    match filter {
        Expr::Compare(_, _, rhs) => {
            assert!(
                matches!(rhs.as_ref(), Expr::Constant(3)),
                "BOTH should be FLAG_A|FLAG_B = 3, got {rhs:?}"
            );
        }
        other => panic!("expected Compare, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 11.5: Cycle detection
// ---------------------------------------------------------------------------

#[test]
fn adversarial_three_way_use_cycle() {
    // a -> b -> c -> a
    let input = r#"
        POLICY a { USE b }
        POLICY b { USE c }
        POLICY c { USE a }
        USE a DEFAULT KILL
    "#;
    let err = parse_and_resolve(input).unwrap_err();
    match &err {
        Error::CircularUse { .. } => {}
        other => panic!("expected CircularUse, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// 11.6: Argument name -> index mapping
// ---------------------------------------------------------------------------

#[test]
fn adversarial_all_six_arguments_mapped() {
    // Verify all 6 arg positions resolve correctly.
    let input = r#"
        POLICY test {
            ALLOW {
                mmap(addr, len, prot, flags, fd, offset) {
                    addr == 0 && len == 0 && prot == 0 && flags == 0 && fd == 0 && offset == 0
                }
            }
        }
        USE test DEFAULT KILL
    "#;
    let resolved = parse_and_resolve(input).unwrap();
    let filter = resolved.entries[0].filter.as_ref().unwrap();
    // Walk the AND chain and collect all arg indices
    fn collect_arg_indices(expr: &Expr) -> Vec<u8> {
        match expr {
            Expr::And(a, b) => {
                let mut v = collect_arg_indices(a);
                v.extend(collect_arg_indices(b));
                v
            }
            Expr::Compare(lhs, _, _) => match lhs.as_ref() {
                Expr::Arg(i) => vec![*i],
                _ => vec![],
            },
            _ => vec![],
        }
    }
    let indices = collect_arg_indices(filter);
    assert_eq!(indices, vec![0, 1, 2, 3, 4, 5], "expected arg0-arg5");
}

// ---------------------------------------------------------------------------
// 11.7: Constant folding
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 11.8: Undeclared argument error
// ---------------------------------------------------------------------------

#[test]
fn adversarial_undeclared_arg_in_masked_expr() {
    // Use an undeclared arg name in a masked expression.
    let input = r#"
        POLICY test {
            ALLOW {
                write(fd, buf, count) { (unknown_arg & 0x4) == 0 }
            }
        }
        USE test DEFAULT KILL
    "#;
    let err = parse_and_resolve(input).unwrap_err();
    match &err {
        Error::UndeclaredArgument { name, syscall, .. } => {
            assert_eq!(name, "unknown_arg");
            assert_eq!(syscall, "write");
        }
        other => panic!("expected UndeclaredArgument, got {other}"),
    }
}

#[test]
fn adversarial_undeclared_arg_no_args_declared() {
    // Syscall with no arg declaration but filter references an arg.
    let input = r#"
        POLICY test {
            ALLOW {
                write { fd == 1 }
            }
        }
        USE test DEFAULT KILL
    "#;
    let err = parse_and_resolve(input).unwrap_err();
    match &err {
        Error::UndeclaredArgument { name, .. } => {
            assert_eq!(name, "fd");
        }
        other => panic!("expected UndeclaredArgument, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// 11.9: Parser tests (verified above by running full suite)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Invariant: No panics on malformed input
// ---------------------------------------------------------------------------

#[test]
fn adversarial_empty_input_no_panic() {
    // Empty input is valid grammar (zero top-level items). It should not panic.
    // Resolution will fail because there's no USE statement.
    let pf = parse_and_validate("");
    // Either it parses to an empty file or errors -- both are fine as long as no panic.
    if let Ok(pf) = pf {
        let err = resolve::resolve(&pf).unwrap_err();
        let _ = err.to_string(); // must not panic
    }
}

#[test]
fn adversarial_garbage_input() {
    let result = parse_and_validate("this is not valid policy text at all!!!");
    assert!(result.is_err(), "garbage input should error");
}

#[test]
fn adversarial_missing_use_statement() {
    // Valid policies but no USE statement -- resolution should error.
    let input = r#"
        POLICY test {
            ALLOW { read }
        }
    "#;
    let pf = parse_and_validate(input).unwrap();
    let err = resolve::resolve(&pf).unwrap_err();
    // Should be some form of error, not a panic
    let _ = err.to_string();
}

#[test]
fn adversarial_deeply_nested_boolean() {
    // Deeply nested boolean should not stack overflow.
    let mut expr = "fd == 0".to_string();
    for _ in 0..20 {
        expr = format!("({expr}) || fd == 0");
    }
    let input = format!(
        r#"
        POLICY test {{
            ALLOW {{
                write(fd, buf, count) {{ {expr} }}
            }}
        }}
        USE test DEFAULT KILL
    "#
    );
    let result = parse_and_resolve(&input);
    assert!(
        result.is_ok(),
        "deeply nested boolean should parse: {result:?}"
    );
}
