//! AST data types for the seccomp policy DSL.

/// A byte-offset span into the original policy source text.
///
/// Used to attach source locations to AST nodes so that downstream error
/// messages can point at the offending identifier. `start` is inclusive,
/// `end` is exclusive. Both are byte offsets, not character indices.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}

/// A parsed seccomp policy file.
#[derive(Debug, Default)]
pub struct PolicyFile {
    /// `#include` directives to resolve.
    pub(crate) includes: Vec<Include>,
    /// `#define` constants (name -> value).
    pub(crate) defines: Vec<(String, Expr)>,
    /// Named policies.
    pub(crate) policies: Vec<Policy>,
    /// Top-level `USE ... DEFAULT ...` statement.
    pub(crate) use_stmt: Option<UseStmt>,
}

/// A parsed `#include "filename"` directive.
#[derive(Debug)]
pub(crate) struct Include {
    /// The filename as written in the directive, with surrounding quotes
    /// stripped.
    pub(crate) filename: String,
    /// Source span of the entire directive (from `#include` through the
    /// closing quote), used to locate include-resolution errors.
    pub(crate) span: Span,
}

impl PolicyFile {
    /// Number of `#define` directives in the file.
    #[cfg(test)]
    pub fn define_count(&self) -> usize {
        self.defines.len()
    }

    /// Number of named policies in the file.
    #[cfg(test)]
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Whether a top-level `USE ... DEFAULT ...` statement is present.
    #[cfg(test)]
    pub fn has_use_stmt(&self) -> bool {
        self.use_stmt.is_some()
    }
}

/// A named policy containing action blocks and references to other policies.
#[derive(Debug)]
pub(crate) struct Policy {
    pub(crate) name: String,
    pub(crate) entries: Vec<PolicyEntry>,
}

/// An entry within a policy: either an action block or a `USE` reference.
#[derive(Debug)]
pub(crate) enum PolicyEntry {
    ActionBlock(ActionBlock),
    /// `USE other_policy` — carries the span of the referenced name so
    /// diagnostics can point at it.
    UseRef(String, Span),
}

/// An action block mapping an action to a set of syscall rules.
#[derive(Debug)]
pub(crate) struct ActionBlock {
    pub(crate) action: Action,
    pub(crate) rules: Vec<SyscallRule>,
}

/// A seccomp return action.
#[derive(Debug, Clone)]
pub(crate) enum Action {
    Allow,
    Kill,
    KillProcess,
    Log,
    UserNotif,
    Errno(Expr),
    Trap(Expr),
    Trace(Expr),
}

/// A syscall rule with optional argument names and filter expression.
#[derive(Debug)]
pub(crate) struct SyscallRule {
    /// Syscall name (e.g., "write", "mmap").
    pub(crate) name: String,
    /// Source span of the syscall name (for "unknown syscall" diagnostics).
    pub(crate) name_span: Span,
    /// Named arguments, if declared (e.g., ["fd", "buf", "count"]).
    pub(crate) args: Vec<String>,
    /// Optional boolean filter on arguments.
    pub(crate) filter: Option<BoolExpr>,
}

/// Boolean expression tree for argument filtering.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum BoolExpr {
    /// Comparison: lhs op rhs
    Compare(CmpLhs, CmpOp, Expr),
    /// Logical AND
    And(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical OR (includes comma-separated OR)
    Or(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical NOT
    Not(Box<BoolExpr>),
    /// Boolean literal (produced by constant folding).
    Literal(bool),
}

/// Left-hand side of a comparison.
#[derive(Debug)]
pub(crate) enum CmpLhs {
    /// Plain argument name with its source span.
    Arg(String, Span),
    /// Masked argument: (arg & mask). Span covers the arg name.
    Masked(String, Span, Expr),
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A value expression (integer literal, identifier, or bitwise-OR combination).
#[derive(Debug, Clone)]
pub(crate) enum Expr {
    /// Integer literal.
    Number(u64),
    /// Identifier (argument name or #define constant), with source span.
    Ident(String, Span),
    /// Bitwise OR of sub-expressions: `O_RDWR | O_CREAT`.
    BitOr(Vec<Expr>),
}

/// Top-level `USE policy1, policy2 DEFAULT action` statement.
#[derive(Debug)]
pub(crate) struct UseStmt {
    /// Policy names with their source spans.
    pub(crate) policies: Vec<(String, Span)>,
    pub(crate) default_action: Action,
}
