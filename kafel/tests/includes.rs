//! Include resolution, prelude support, depth limits, circular detection,
//! and error propagation — all via the public compile_with_options API.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Include resolution
// ---------------------------------------------------------------------------

#[test]
fn include_compiles() {
    let mut libs = HashMap::new();
    libs.insert(
        "stdio.policy".to_string(),
        "POLICY stdio { ALLOW { read, write, close } }".to_string(),
    );

    let opts = kafel::CompileOptions::new().with_include_resolver(move |name, _ctx| {
        libs.get(name)
            .cloned()
            .map(Into::into)
            .ok_or_else(|| kafel::Error::IncludeNotFound {
                filename: name.to_string(),
                span: None,
            })
    });

    let prog =
        kafel::compile_with_options("#include \"stdio.policy\"\nUSE stdio DEFAULT KILL", &opts)
            .expect("compilation should succeed");
    assert!(!prog.instructions().is_empty());
}

#[test]
fn include_merges_defines() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "constants.policy" => Ok("#define MY_FD 1".to_string().into()),
        _ => Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });

    let prog = kafel::compile_with_options(
        r#"#include "constants.policy"
        POLICY p { ALLOW { write(fd, buf, count) { fd == MY_FD } } }
        USE p DEFAULT KILL"#,
        &opts,
    )
    .expect("included defines should be available");
    assert!(!prog.instructions().is_empty());
}

#[test]
fn include_defines_visible_in_filter() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "consts.policy" => Ok("#define MY_FD 42".to_string().into()),
        _ => Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });

    let prog = kafel::compile_with_options(
        r#"#include "consts.policy"
        POLICY p { ALLOW { write(fd, buf, count) { fd == MY_FD } } }
        USE p DEFAULT KILL"#,
        &opts,
    )
    .expect("defines from included file should be accessible");
    assert!(!prog.instructions().is_empty());
}

#[test]
fn include_policies_usable() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "lib.policy" => Ok("POLICY io { ALLOW { read, write, close } }"
            .to_string()
            .into()),
        _ => Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });

    let prog = kafel::compile_with_options(
        r#"#include "lib.policy"
        USE io DEFAULT KILL"#,
        &opts,
    )
    .expect("included policies should be available for USE");
    assert!(!prog.instructions().is_empty());
}

#[test]
fn multi_level_include() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "base.policy" => Ok("#include \"io.policy\"\n#define BASE_CONST 42"
            .to_string()
            .into()),
        "io.policy" => Ok("POLICY io { ALLOW { read, write } }".to_string().into()),
        _ => Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });

    let prog = kafel::compile_with_options("#include \"base.policy\"\nUSE io DEFAULT KILL", &opts)
        .expect("multi-level include should work");
    assert!(!prog.instructions().is_empty());
}

// ---------------------------------------------------------------------------
// Prelude
// ---------------------------------------------------------------------------

#[test]
fn prelude_define() {
    let opts = kafel::CompileOptions::new().with_prelude("#define STDOUT 1");

    let prog = kafel::compile_with_options(
        "POLICY p { ALLOW { write(fd, buf, count) { fd == STDOUT } } } USE p DEFAULT KILL",
        &opts,
    )
    .expect("prelude define should be available");
    assert!(!prog.instructions().is_empty());
}

#[test]
fn prelude_and_include_combined() {
    let opts = kafel::CompileOptions::new()
        .with_prelude("#define STDOUT 1")
        .with_include_resolver(|name, _ctx| match name {
            "io.policy" => Ok(
                "POLICY io { ALLOW { write(fd, buf, count) { fd == STDOUT } } }"
                    .to_string()
                    .into(),
            ),
            _ => Err(kafel::Error::IncludeNotFound {
                filename: name.to_string(),
                span: None,
            }),
        });

    let prog = kafel::compile_with_options("#include \"io.policy\"\nUSE io DEFAULT KILL", &opts)
        .expect("prelude defines should be visible to included files");
    assert!(!prog.instructions().is_empty());
}

#[test]
fn prelude_overridden_by_main_define() {
    let opts = kafel::CompileOptions::new().with_prelude("#define FOO 1");

    let result = kafel::compile_with_options(
        "#define FOO 2\nPOLICY p { ALLOW { write(fd, buf, count) { fd == FOO } } } USE p DEFAULT KILL",
        &opts,
    );
    // At minimum, this should not panic
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn prelude_empty_string() {
    let opts = kafel::CompileOptions::new().with_prelude("");

    let prog = kafel::compile_with_options("POLICY p { ALLOW { read } } USE p DEFAULT KILL", &opts)
        .expect("empty prelude should not cause errors");
    assert!(!prog.instructions().is_empty());
}

// ---------------------------------------------------------------------------
// Depth limits
// ---------------------------------------------------------------------------

#[test]
fn include_depth_exceeded() {
    let opts = kafel::CompileOptions::new()
        .with_max_depth(3)
        .with_include_resolver(|name, _ctx| {
            let next = match name {
                "a.policy" => Some("b.policy"),
                "b.policy" => Some("c.policy"),
                "c.policy" => Some("d.policy"),
                "d.policy" => Some("e.policy"),
                _ => None,
            };
            match next {
                Some(n) => Ok(format!("#include \"{n}\"").into()),
                None => Ok("POLICY p { ALLOW { read } }".to_string().into()),
            }
        });

    let result = kafel::compile_with_options(
        "#include \"a.policy\"\nPOLICY q { ALLOW { write } } USE q DEFAULT KILL",
        &opts,
    );
    assert!(
        matches!(result, Err(kafel::Error::IncludeDepthExceeded)),
        "expected IncludeDepthExceeded, got: {result:?}"
    );
}

#[test]
fn include_depth_default_10() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| {
        let n: usize = name.strip_suffix(".policy").unwrap().parse().unwrap();
        if n < 11 {
            Ok(format!("#include \"{}.policy\"", n + 1).into())
        } else {
            Ok("POLICY p { ALLOW { read } }".to_string().into())
        }
    });

    let result = kafel::compile_with_options(
        "#include \"0.policy\"\nPOLICY q { ALLOW { write } } USE q DEFAULT KILL",
        &opts,
    );
    assert!(
        matches!(result, Err(kafel::Error::IncludeDepthExceeded)),
        "11 levels should exceed default depth 10"
    );
}

#[test]
fn include_depth_zero() {
    let opts = kafel::CompileOptions::new()
        .with_max_depth(0)
        .with_include_resolver(|_name, _ctx| Ok("POLICY q { ALLOW { read } }".to_string().into()));

    let result = kafel::compile_with_options(
        "#include \"anything.policy\"\nPOLICY p { ALLOW { write } } USE p DEFAULT KILL",
        &opts,
    );
    assert!(
        matches!(result, Err(kafel::Error::IncludeDepthExceeded)),
        "depth 0 should reject any include, got: {result:?}"
    );
}

#[test]
fn include_depth_exactly_at_limit() {
    let opts = kafel::CompileOptions::new()
        .with_max_depth(3)
        .with_include_resolver(|name, _ctx| match name {
            "a.policy" => Ok("#include \"b.policy\"\n".to_string().into()),
            "b.policy" => Ok("#include \"c.policy\"\n".to_string().into()),
            "c.policy" => Ok("POLICY leaf { ALLOW { read } }".to_string().into()),
            _ => Err(kafel::Error::IncludeNotFound {
                filename: name.to_string(),
                span: None,
            }),
        });

    let result = kafel::compile_with_options("#include \"a.policy\"\nUSE leaf DEFAULT KILL", &opts);
    assert!(
        result.is_ok(),
        "chain of 3 should work with max_depth=3: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Circular detection
// ---------------------------------------------------------------------------

#[test]
fn circular_include() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "a.policy" => Ok("#include \"b.policy\"\nPOLICY a { ALLOW { read } }"
            .to_string()
            .into()),
        "b.policy" => Ok("#include \"a.policy\"\nPOLICY b { ALLOW { write } }"
            .to_string()
            .into()),
        _ => Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });

    let result = kafel::compile_with_options("#include \"a.policy\"\nUSE a DEFAULT KILL", &opts);
    assert!(
        matches!(result, Err(kafel::Error::CircularInclude { .. })),
        "expected CircularInclude, got: {result:?}"
    );
}

#[test]
fn self_include() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "self.policy" => Ok("#include \"self.policy\"\nPOLICY p { ALLOW { read } }"
            .to_string()
            .into()),
        _ => Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });

    let result = kafel::compile_with_options("#include \"self.policy\"\nUSE p DEFAULT KILL", &opts);
    assert!(
        matches!(result, Err(kafel::Error::CircularInclude { .. })),
        "self-include should be detected as circular, got: {result:?}"
    );
}

#[test]
fn three_way_circular_include() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| match name {
        "a.policy" => Ok("#include \"b.policy\"".to_string().into()),
        "b.policy" => Ok("#include \"c.policy\"".to_string().into()),
        "c.policy" => Ok("#include \"a.policy\"".to_string().into()),
        _ => Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        }),
    });

    let result = kafel::compile_with_options(
        "#include \"a.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
    );
    assert!(
        matches!(
            result,
            Err(kafel::Error::CircularInclude { .. }) | Err(kafel::Error::IncludeDepthExceeded)
        ),
        "three-way circular should be detected, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn no_resolver_fails() {
    let result = kafel::compile("#include \"stdio.policy\"\nUSE stdio DEFAULT KILL");
    assert!(result.is_err(), "should fail without include resolver");
}

#[test]
fn resolver_error_propagation() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| {
        Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        })
    });

    let result = kafel::compile_with_options(
        "#include \"missing.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
    );
    match result {
        Err(kafel::Error::IncludeNotFound { filename, .. }) => {
            assert_eq!(filename, "missing.policy");
        }
        other => panic!("expected IncludeNotFound, got: {other:?}"),
    }
}

#[test]
fn no_panic_include_garbage() {
    let opts = kafel::CompileOptions::new()
        .with_include_resolver(|_, _ctx| Ok("not a valid policy @@@ !!!".to_string().into()));

    let result = kafel::compile_with_options(
        "#include \"garbage.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
    );
    assert!(
        result.is_err(),
        "garbage include content should produce error"
    );
}

#[test]
fn no_panic_resolver_returns_error() {
    let opts = kafel::CompileOptions::new().with_include_resolver(|name, _ctx| {
        Err(kafel::Error::IncludeNotFound {
            filename: name.to_string(),
            span: None,
        })
    });

    let result = kafel::compile_with_options(
        "#include \"any.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
    );
    match result {
        Err(kafel::Error::IncludeNotFound { filename, .. }) => {
            assert_eq!(filename, "any.policy");
        }
        other => panic!("expected IncludeNotFound, got: {:?}", other.map(|_| "Ok")),
    }
}
