//! Error types for the kafel policy compiler.

use std::fmt::Write as _;

use crate::ast::Span;

/// The sole error type for policy compilation.
///
/// All failure paths in parsing, resolution, include processing, and
/// BPF codegen produce this error. It implements [`std::fmt::Display`]
/// and [`std::error::Error`] for ergonomic error handling and chaining.
///
/// Most variants carry a [`Span`] pointing into the original policy source.
/// Pair an error with its source text and pass it to [`render_diagnostic`]
/// to produce a multi-line report with a rendered source snippet and caret.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The policy text failed to parse.
    #[error("parse error: {message}")]
    Parse {
        /// Human-readable description.
        message: String,
        /// Source span of the offending token, if known.
        span: Option<Span>,
    },
    /// A syscall name in the policy has no known number.
    #[error("unknown syscall: '{name}'")]
    UnknownSyscall {
        /// The unrecognized syscall name.
        name: String,
        /// Source span of the name. `None` when constructed outside the
        /// parser (e.g. via the public [`crate::resolve_syscall`] helper).
        span: Option<Span>,
    },
    /// An identifier in an expression could not be resolved to a `#define`
    /// constant or argument name.
    #[error("undefined identifier: '{name}'")]
    UndefinedIdentifier {
        /// The unresolved identifier.
        name: String,
        /// Source span of the identifier.
        span: Option<Span>,
    },
    /// An argument name used in a filter was not declared in the syscall's
    /// argument list.
    #[error("undeclared argument '{name}' in syscall '{syscall}'")]
    UndeclaredArgument {
        /// The undeclared argument name.
        name: String,
        /// The syscall rule it appeared in.
        syscall: String,
        /// Source span of the offending identifier in the filter.
        span: Option<Span>,
    },
    /// A `USE` reference forms a cycle.
    #[error("circular USE reference involving policy '{policy}'")]
    CircularUse {
        /// The policy name where the cycle was detected.
        policy: String,
        /// Source span of the `USE` that closed the cycle.
        span: Option<Span>,
    },
    /// A `USE` reference names a policy that does not exist.
    #[error("USE references undefined policy '{name}'")]
    UndefinedPolicy {
        /// The missing policy name.
        name: String,
        /// Source span of the referenced name.
        span: Option<Span>,
    },
    /// An error occurred during BPF code generation.
    #[error("codegen error: {message}")]
    Codegen {
        /// Human-readable description of the codegen failure.
        message: String,
        /// Source span, if the error can be traced to a specific token.
        span: Option<Span>,
    },
    /// An `#include` directive referenced a file that the resolver could not find.
    #[error("include file not found: '{filename}'")]
    IncludeNotFound {
        /// The filename from the `#include` directive.
        filename: String,
        /// Source span of the directive.
        span: Option<Span>,
    },
    /// Recursive `#include` directives exceeded the configured depth limit.
    #[error("include depth exceeded maximum limit")]
    IncludeDepthExceeded,
    /// A circular `#include` chain was detected.
    #[error("circular include detected: '{filename}'")]
    CircularInclude {
        /// The filename that completed the cycle.
        filename: String,
        /// Source span of the directive that closed the cycle.
        span: Option<Span>,
    },
}

impl Error {
    /// Return the source span attached to this error, if any.
    pub fn span(&self) -> Option<Span> {
        match self {
            Error::Parse { span, .. }
            | Error::UnknownSyscall { span, .. }
            | Error::UndefinedIdentifier { span, .. }
            | Error::UndeclaredArgument { span, .. }
            | Error::CircularUse { span, .. }
            | Error::UndefinedPolicy { span, .. }
            | Error::Codegen { span, .. }
            | Error::IncludeNotFound { span, .. }
            | Error::CircularInclude { span, .. } => *span,
            Error::IncludeDepthExceeded => None,
        }
    }
}

/// Render an error with source context as a multi-line diagnostic.
///
/// Produces output similar in spirit to rustc:
///
/// ```text
/// error: unknown syscall: 'writee'
///   --> policy.kafel:4:5
///    |
///  4 |     writee,
///    |     ^^^^^^
/// ```
///
/// If the error has no span, only the one-line `error: <message>` header is
/// produced. `filename` is used only for the `-->` header; pass `None` to
/// show `<input>` instead.
pub fn render_diagnostic(err: &Error, source: &str, filename: Option<&str>) -> String {
    let mut out = String::new();
    writeln!(out, "error: {err}").unwrap();
    if let Some(span) = err.span() {
        render_snippet(&mut out, source, filename, span);
    }
    out
}

fn render_snippet(out: &mut String, source: &str, filename: Option<&str>, span: Span) {
    let start = (span.start as usize).min(source.len());
    let end = (span.end as usize).min(source.len()).max(start);

    let (line, col) = line_col(source, start as u32);
    let line_start = line_start_byte(source, start);
    let line_text_end = source[line_start..]
        .find('\n')
        .map(|i| line_start + i)
        .unwrap_or(source.len());
    let line_text = &source[line_start..line_text_end];

    // Compute caret width: the span may extend past the end of the line
    // (e.g. when it crosses into another line or when end == start). Clamp
    // to at least 1 character and don't run off the end of the line.
    let caret_start_col = col; // 1-based column within the line
    let span_byte_len_on_line = end.min(line_text_end).saturating_sub(start);
    let caret_char_len = source[start..start + span_byte_len_on_line]
        .chars()
        .count()
        .max(1);

    let file = filename.unwrap_or("<input>");
    let num = line.to_string();
    let gutter = " ".repeat(num.len());

    writeln!(out, "{gutter}--> {file}:{line}:{caret_start_col}").unwrap();
    writeln!(out, "{gutter} |").unwrap();
    writeln!(out, "{num} | {line_text}").unwrap();
    let pad = " ".repeat(caret_start_col.saturating_sub(1));
    let carets = "^".repeat(caret_char_len);
    writeln!(out, "{gutter} | {pad}{carets}").unwrap();
}

/// Return the 1-based (line, column) for a byte offset in `source`.
/// Column counts characters, not bytes, so multi-byte UTF-8 is handled.
fn line_col(source: &str, byte: u32) -> (usize, usize) {
    let target = (byte as usize).min(source.len());
    let mut line = 1usize;
    let mut col = 1usize;
    let mut idx = 0usize;
    for ch in source.chars() {
        if idx >= target {
            return (line, col);
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
        idx += ch.len_utf8();
    }
    (line, col)
}

/// Return the byte offset of the start of the line containing `byte`.
fn line_start_byte(source: &str, byte: usize) -> usize {
    source[..byte].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_col_single_line() {
        let src = "hello world";
        assert_eq!(line_col(src, 0), (1, 1));
        assert_eq!(line_col(src, 6), (1, 7));
    }

    #[test]
    fn line_col_multi_line() {
        let src = "foo\nbar\nbaz";
        assert_eq!(line_col(src, 0), (1, 1));
        assert_eq!(line_col(src, 4), (2, 1));
        assert_eq!(line_col(src, 8), (3, 1));
        assert_eq!(line_col(src, 10), (3, 3));
    }

    #[test]
    fn render_snippet_points_at_identifier() {
        let src = "POLICY p {\n    ALLOW { writee }\n}\nUSE p DEFAULT KILL\n";
        let start = src.find("writee").unwrap() as u32;
        let end = start + 6;
        let err = Error::UnknownSyscall {
            name: "writee".to_string(),
            span: Some(Span::new(start, end)),
        };
        let out = render_diagnostic(&err, src, Some("policy.kafel"));
        assert!(out.contains("error: unknown syscall: 'writee'"), "{out}");
        assert!(out.contains("--> policy.kafel:2:13"), "{out}");
        assert!(out.contains("2 |     ALLOW { writee }"), "{out}");
        assert!(out.contains("^^^^^^"), "{out}");
    }

    #[test]
    fn render_without_span_is_header_only() {
        let err = Error::IncludeDepthExceeded;
        let out = render_diagnostic(&err, "", None);
        assert_eq!(out, "error: include depth exceeded maximum limit\n");
    }
}
