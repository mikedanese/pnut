//! Include system error tests using internal parser APIs.
//!
//! Tests include resolution, depth limiting, and circular detection
//! via `parse_with_includes` directly.

use std::collections::HashSet;

use crate::codegen::CompileOptions;
use crate::error::Error;
use crate::parser;

// ---------------------------------------------------------------------------
// Include not found (no resolver)
// ---------------------------------------------------------------------------

#[test]
fn include_without_resolver_errors() {
    let opts = CompileOptions::new();
    let mut seen = HashSet::new();
    let result = parser::parse_with_includes(
        "#include \"missing.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    );
    assert!(
        matches!(result, Err(Error::IncludeNotFound { ref filename, .. }) if filename == "missing.policy"),
        "expected IncludeNotFound, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Circular include (self-referential)
// ---------------------------------------------------------------------------

#[test]
fn self_include_detected() {
    let opts = CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "self.policy" => Ok("#include \"self.policy\"\nPOLICY p { ALLOW { read } }"
            .to_string()
            .into()),
        _ => Err(Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });
    let mut seen = HashSet::new();
    let result = parser::parse_with_includes(
        "#include \"self.policy\"\nUSE p DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    );
    assert!(
        matches!(result, Err(Error::CircularInclude { .. })),
        "expected CircularInclude, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Circular include (three-way cycle)
// ---------------------------------------------------------------------------

#[test]
fn three_way_circular_include() {
    let opts = CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "a.policy" => Ok("#include \"b.policy\"".to_string().into()),
        "b.policy" => Ok("#include \"c.policy\"".to_string().into()),
        "c.policy" => Ok("#include \"a.policy\"".to_string().into()),
        _ => Err(Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });
    let mut seen = HashSet::new();
    let result = parser::parse_with_includes(
        "#include \"a.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    );
    assert!(
        matches!(
            result,
            Err(Error::CircularInclude { .. }) | Err(Error::IncludeDepthExceeded)
        ),
        "expected circular or depth exceeded, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Include depth exceeded
// ---------------------------------------------------------------------------

#[test]
fn include_depth_zero_rejects_any_include() {
    let opts = CompileOptions::new()
        .with_max_depth(0)
        .with_include_resolver(|_, _ctx| Ok("POLICY q { ALLOW { read } }".to_string().into()));
    let mut seen = HashSet::new();
    let result = parser::parse_with_includes(
        "#include \"any.policy\"\nPOLICY p { ALLOW { write } } USE p DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    );
    assert!(
        matches!(result, Err(Error::IncludeDepthExceeded)),
        "expected IncludeDepthExceeded, got {result:?}"
    );
}

#[test]
fn include_chain_at_exact_depth_limit() {
    let opts = CompileOptions::new()
        .with_max_depth(3)
        .with_include_resolver(|name, _ctx| match name {
            "a.policy" => Ok("#include \"b.policy\"\n".to_string().into()),
            "b.policy" => Ok("#include \"c.policy\"\n".to_string().into()),
            "c.policy" => Ok("POLICY leaf { ALLOW { read } }".to_string().into()),
            _ => Err(Error::IncludeNotFound {
                filename: name.to_string(),
                span: None,
            }),
        });
    let mut seen = HashSet::new();
    let result = parser::parse_with_includes(
        "#include \"a.policy\"\nUSE leaf DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    );
    assert!(
        result.is_ok(),
        "depth 3 chain with max_depth=3 should succeed: {result:?}"
    );
}

#[test]
fn include_chain_one_past_depth_limit() {
    let opts = CompileOptions::new()
        .with_max_depth(2)
        .with_include_resolver(|name, _ctx| match name {
            "a.policy" => Ok("#include \"b.policy\"\n".to_string().into()),
            "b.policy" => Ok("#include \"c.policy\"\n".to_string().into()),
            "c.policy" => Ok("POLICY leaf { ALLOW { read } }".to_string().into()),
            _ => Err(Error::IncludeNotFound {
                filename: name.to_string(),
                span: None,
            }),
        });
    let mut seen = HashSet::new();
    let result = parser::parse_with_includes(
        "#include \"a.policy\"\nUSE leaf DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    );
    assert!(
        matches!(result, Err(Error::IncludeDepthExceeded)),
        "depth 3 chain with max_depth=2 should fail: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Include with garbage content
// ---------------------------------------------------------------------------

#[test]
fn include_garbage_content_errors() {
    let opts = CompileOptions::new()
        .with_include_resolver(|_, _ctx| Ok("not a valid policy @@@ !!!".to_string().into()));
    let mut seen = HashSet::new();
    let result = parser::parse_with_includes(
        "#include \"garbage.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    );
    assert!(
        matches!(result, Err(Error::Parse { .. })),
        "garbage include should produce ParseError, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Include defines visible in main policy
// ---------------------------------------------------------------------------

#[test]
fn included_defines_merge_into_main() {
    let opts = CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "consts.policy" => Ok("#define MY_FD 42".to_string().into()),
        _ => Err(Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });
    let mut seen = HashSet::new();
    let pf = parser::parse_with_includes(
        "#include \"consts.policy\"\nPOLICY p { ALLOW { write(fd, buf, count) { fd == MY_FD } } } USE p DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    ).unwrap();
    parser::validate(&pf).unwrap();
    // MY_FD should be in the defines
    assert!(pf.defines.iter().any(|(name, _)| name == "MY_FD"));
}

// ---------------------------------------------------------------------------
// Include policies available for USE
// ---------------------------------------------------------------------------

#[test]
fn included_policies_available_for_use() {
    let opts = CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "lib.policy" => Ok("POLICY io { ALLOW { read, write, close } }"
            .to_string()
            .into()),
        _ => Err(Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });
    let mut seen = HashSet::new();
    let pf = parser::parse_with_includes(
        "#include \"lib.policy\"\nUSE io DEFAULT KILL",
        &opts,
        &mut seen,
        0,
        None,
    )
    .unwrap();
    parser::validate(&pf).unwrap();
    // Should have the "io" policy from the include
    assert!(pf.policies.iter().any(|p| p.name == "io"));
}
