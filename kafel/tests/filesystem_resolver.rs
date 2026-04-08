//! Tests for FilesystemResolver — real filesystem includes.

use std::fs;
use tempfile::TempDir;

fn test_dir() -> TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn relative_include_from_base_dir() {
    let tmp = test_dir();
    let dir = tmp.path();
    fs::write(
        dir.join("io.policy"),
        "POLICY io { ALLOW { read, write, close } }",
    )
    .unwrap();

    let resolver = kafel::FilesystemResolver::new(dir);
    let opts = kafel::CompileOptions::new()
        .with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));

    let prog =
        kafel::compile_with_options("#include \"io.policy\"\nUSE io DEFAULT KILL", &opts).unwrap();
    assert!(!prog.instructions().is_empty());
}

#[test]
fn nested_relative_include() {
    let tmp = test_dir();
    let dir = tmp.path();
    let sub = dir.join("sub");
    fs::create_dir_all(&sub).unwrap();

    fs::write(sub.join("base.policy"), "#include \"leaf.policy\"\n").unwrap();
    fs::write(sub.join("leaf.policy"), "POLICY leaf { ALLOW { read } }").unwrap();

    let resolver = kafel::FilesystemResolver::new(dir);
    let opts = kafel::CompileOptions::new()
        .with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));

    let prog =
        kafel::compile_with_options("#include \"sub/base.policy\"\nUSE leaf DEFAULT KILL", &opts)
            .unwrap();
    assert!(!prog.instructions().is_empty());
}

#[test]
fn absolute_path_include() {
    let tmp = test_dir();
    let dir = tmp.path();
    let abs_path = dir.join("abs.policy");
    fs::write(&abs_path, "POLICY abs { ALLOW { read, write } }").unwrap();

    let resolver = kafel::FilesystemResolver::new(dir);
    let opts = kafel::CompileOptions::new()
        .with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));

    let policy = format!("#include \"{}\"\nUSE abs DEFAULT KILL", abs_path.display());
    let prog = kafel::compile_with_options(&policy, &opts).unwrap();
    assert!(!prog.instructions().is_empty());
}

#[test]
fn missing_file_returns_include_not_found() {
    let tmp = test_dir();
    let dir = tmp.path();
    let resolver = kafel::FilesystemResolver::new(dir);
    let opts = kafel::CompileOptions::new()
        .with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));

    let result = kafel::compile_with_options(
        "#include \"nonexistent.policy\"\nPOLICY p { ALLOW { read } } USE p DEFAULT KILL",
        &opts,
    );
    assert!(
        matches!(result, Err(kafel::Error::IncludeNotFound { .. })),
        "expected IncludeNotFound, got: {result:?}"
    );
}

#[test]
fn dotdot_traversal_in_nested_include() {
    let tmp = test_dir();
    let dir = tmp.path();
    let sub = dir.join("sub");
    fs::create_dir_all(&sub).unwrap();

    fs::write(
        dir.join("common.policy"),
        "POLICY common { ALLOW { read } }",
    )
    .unwrap();
    fs::write(sub.join("inner.policy"), "#include \"../common.policy\"\n").unwrap();

    let resolver = kafel::FilesystemResolver::new(dir);
    let opts = kafel::CompileOptions::new()
        .with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));

    let prog = kafel::compile_with_options(
        "#include \"sub/inner.policy\"\nUSE common DEFAULT KILL",
        &opts,
    )
    .unwrap();
    assert!(!prog.instructions().is_empty());
}
