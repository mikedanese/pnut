//! Kafel-inspired seccomp policy compiler.
//!
//! This crate parses a Kafel-inspired seccomp policy DSL, resolves names
//! and constants, and compiles to BPF bytecode ready for
//! `seccomp(SECCOMP_SET_MODE_FILTER)`.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! // Compile a simple policy that allows read, write, close
//! // and kills on everything else.
//! let program = kafel::compile(
//!     "POLICY p { ALLOW { read, write, close } } USE p DEFAULT KILL"
//! ).unwrap();
//!
//! // The BPF program is ready to load.
//! assert!(!program.instructions().is_empty());
//!
//! // Install the filter into the current process.
//! // WARNING: this constrains the process permanently.
//! // kafel::install_filter(&program).unwrap();
//! ```
//!
//! # Include Support
//!
//! Use [`CompileOptions`] to supply an include resolver for `#include`
//! directives, or a prelude string with shared definitions:
//!
//! ```rust,no_run
//! use kafel::{CompileOptions, Error, compile_with_options};
//! use std::collections::HashMap;
//!
//! let mut libs = HashMap::new();
//! libs.insert("stdio.policy".to_string(),
//!     "POLICY stdio { ALLOW { read, write, close } }".to_string());
//!
//! let opts = CompileOptions::new()
//!     .with_include_resolver(move |name, _ctx| {
//!         libs.get(name)
//!             .cloned()
//!             .map(Into::into)
//!             .ok_or_else(|| Error::IncludeNotFound {
//!                 filename: name.to_string(),
//!                 span: None,
//!             })
//!     });
//!
//! let program = compile_with_options(
//!     "#include \"stdio.policy\"\nUSE stdio DEFAULT KILL",
//!     &opts,
//! ).unwrap();
//! ```

pub mod ast;
mod codegen;
mod error;
#[cfg_attr(not(test), allow(dead_code))]
mod interp;
mod parser;
pub mod resolve;
mod resolver;

#[cfg(test)]
mod tests;

/// Built-in kafel seccomp stdlib definitions.
///
/// This prelude is defined in a single [`prelude.policy`](prelude.policy)
/// file and exposes a family of `allow_*` policies that mirror the
/// seccomp-expressible subset of Sandboxed API's `PolicyBuilder` helpers.
///
/// Representative policies include:
/// - `allow_default_policy`
/// - `allow_static_startup`
/// - `allow_dynamic_startup`
/// - `allow_system_malloc`
/// - `allow_safe_fcntl`
///
/// Pass this as the prelude to [`CompileOptions::with_prelude`] to make these
/// builtin policy definitions available to `USE` in any compiled policy.
pub const BUILTIN_PRELUDE: &str = include_str!("prelude.policy");

pub use ast::{CmpOp, Span};
pub use codegen::{
    BpfProgram, CompileOptions, IncludeContext, IncludeResult, compile, compile_with_options,
    install_filter, parse_policy,
};
pub use error::{Error, render_diagnostic};
pub use resolve::{Action, Expr, Policy, PolicyEntry, resolve_syscall};
pub use resolver::FilesystemResolver;
