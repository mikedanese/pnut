//! Seccomp-bpf policy parsing and AST.
//!
//! Parses Kafel into a structured policy representation. The language supports:
//!
//! - **Named policies** with composition via `USE`
//! - **Action blocks**: `ALLOW`, `KILL`, `ERRNO(n)`, `LOG`, `TRAP(n)`
//! - **Syscall argument filtering** with boolean expressions
//! - **Constants** via `#define`
//! - **Bitwise flag composition**: `O_RDWR|O_CREAT`
//!
//! # Example
//!
//! ```text
//! #define STDOUT 1
//! #define STDERR 2
//!
//! POLICY stdio {
//!     ALLOW {
//!         read(fd, buf, count) { fd == 0 },
//!         write(fd, buf, count) { fd == STDOUT || fd == STDERR },
//!         close, dup, dup2, fstat,
//!     }
//! }
//!
//! POLICY deny_dangerous {
//!     KILL { ptrace, process_vm_readv, process_vm_writev }
//!     ERRNO(1) { execve, execveat }
//! }
//!
//! USE stdio, deny_dangerous DEFAULT KILL
//! ```

use pest::Parser;
use pest_derive::Parser;

use crate::ast::*;
use crate::error::Error;

#[derive(Parser)]
#[grammar = "policy.pest"]
struct SeccompParser;

/// Convert a pest `Pair`'s span into our own [`Span`] type.
fn span_of(pair: &pest::iterators::Pair<Rule>) -> Span {
    let s = pair.as_span();
    Span::new(s.start() as u32, s.end() as u32)
}

/// Convert a pest parse error into `Error::Parse`, capturing the byte span
/// of the offending location so diagnostics can render a source snippet.
fn pest_to_parse_error(err: pest::error::Error<Rule>) -> Error {
    let span = match err.location {
        pest::error::InputLocation::Pos(p) => Some(Span::new(p as u32, p as u32 + 1)),
        pest::error::InputLocation::Span((s, e)) => Some(Span::new(s as u32, e as u32)),
    };
    Error::Parse {
        message: err.variant.message().to_string(),
        span,
    }
}

/// Parse and validate a seccomp policy string.
///
/// Parses the DSL into an AST and checks for structural errors:
/// - `USE` references must name policies that exist in the file
/// - The top-level `USE ... DEFAULT ...` statement must reference defined policies
/// - Syscall argument indices must be 0-5
///
/// Returns the validated `PolicyFile` AST.
#[cfg(test)]
pub fn parse_and_validate(input: &str) -> Result<PolicyFile, Error> {
    let policy_file = parse_policy(input).map_err(pest_to_parse_error)?;
    validate_policy(&policy_file)?;
    Ok(policy_file)
}

/// Parse a policy string, resolving `#include` directives but deferring validation.
///
/// This function handles include resolution by calling the resolver callback
/// in `CompileOptions`, tracking include depth and detecting circular includes.
/// Validation is deferred so that the caller can merge additional content
/// (e.g., prelude) before checking structural correctness.
///
/// `parent_filename` is the path/name of the file being parsed, or `None` for
/// the top-level input. It is passed to the include resolver as context so
/// relative paths can resolve against the including file's directory.
pub fn parse_with_includes(
    input: &str,
    options: &crate::codegen::CompileOptions,
    seen_includes: &mut std::collections::HashSet<String>,
    depth: usize,
    parent_filename: Option<&str>,
) -> Result<PolicyFile, Error> {
    let mut policy_file = parse_policy(input).map_err(pest_to_parse_error)?;

    // Process include directives
    let includes = std::mem::take(&mut policy_file.includes);
    for Include {
        filename,
        span: directive_span,
    } in includes
    {
        // Check depth limit
        if depth >= options.max_include_depth {
            return Err(Error::IncludeDepthExceeded);
        }

        // Check for circular includes
        if !seen_includes.insert(filename.clone()) {
            return Err(Error::CircularInclude {
                filename: filename.clone(),
                span: Some(directive_span),
            });
        }

        // Resolve the include
        let resolver = options
            .include_resolver
            .as_ref()
            .ok_or_else(|| Error::IncludeNotFound {
                filename: filename.clone(),
                span: Some(directive_span),
            })?;
        let ctx = crate::codegen::IncludeContext {
            parent: parent_filename,
        };
        // If the resolver returned IncludeNotFound without a span, attach the
        // current directive's span so downstream diagnostics can point at it.
        let result = match resolver(&filename, &ctx) {
            Ok(r) => r,
            Err(Error::IncludeNotFound {
                filename,
                span: None,
            }) => {
                return Err(Error::IncludeNotFound {
                    filename,
                    span: Some(directive_span),
                });
            }
            Err(e) => return Err(e),
        };

        // Use canonical name if provided, otherwise fall back to raw filename.
        let effective_name = result.canonical_name.as_deref().unwrap_or(&filename);

        // Recursively parse the included content
        let included_pf = parse_with_includes(
            &result.contents,
            options,
            seen_includes,
            depth + 1,
            Some(effective_name),
        )?;

        // Merge included content: defines and policies
        policy_file.defines.extend(included_pf.defines);
        policy_file.policies.extend(included_pf.policies);
        // Included files typically don't have USE statements, but if they do,
        // don't override the main file's USE statement.
        if policy_file.use_stmt.is_none() {
            policy_file.use_stmt = included_pf.use_stmt;
        }

        // Remove from seen set after processing (allow same file in
        // different branches, just not in the same ancestor chain)
        seen_includes.remove(&filename);
    }

    Ok(policy_file)
}

/// Validate a parsed (and fully merged) policy file.
///
/// Call this after all include and prelude merging is complete.
pub fn validate(pf: &PolicyFile) -> Result<(), Error> {
    validate_policy(pf)
}

/// Validate a parsed policy file for structural correctness.
fn validate_policy(pf: &PolicyFile) -> Result<(), Error> {
    let defined_names: Vec<&str> = pf.policies.iter().map(|p| p.name.as_str()).collect();

    for policy in &pf.policies {
        for entry in &policy.entries {
            match entry {
                PolicyEntry::ActionBlock(block) => {
                    for rule in &block.rules {
                        if rule.args.len() > 6 {
                            return Err(Error::Parse {
                                message: format!(
                                    "syscall '{}' declares {} arguments (max 6)",
                                    rule.name,
                                    rule.args.len()
                                ),
                                span: Some(rule.name_span),
                            });
                        }
                    }
                }
                PolicyEntry::UseRef(name, span) => {
                    if !defined_names.contains(&name.as_str()) {
                        return Err(Error::UndefinedPolicy {
                            name: name.clone(),
                            span: Some(*span),
                        });
                    }
                }
            }
        }
    }

    if let Some(ref use_stmt) = pf.use_stmt {
        for (name, span) in &use_stmt.policies {
            if !defined_names.contains(&name.as_str()) {
                return Err(Error::UndefinedPolicy {
                    name: name.clone(),
                    span: Some(*span),
                });
            }
        }
    }

    Ok(())
}

/// Parse a seccomp policy string into a [`PolicyFile`].
fn parse_policy(input: &str) -> Result<PolicyFile, pest::error::Error<Rule>> {
    let pairs = SeccompParser::parse(Rule::file, input)?;
    let mut policy_file = PolicyFile::default();

    for pair in pairs.into_iter().next().unwrap().into_inner() {
        match pair.as_rule() {
            Rule::include_directive => {
                let span = span_of(&pair);
                let string_lit = pair.into_inner().next().unwrap();
                // Strip the surrounding quotes from the string literal
                let raw = string_lit.as_str();
                let filename = raw[1..raw.len() - 1].to_string();
                policy_file.includes.push(Include { filename, span });
            }
            Rule::define => {
                let mut inner = pair.into_inner();
                let name = inner.next().unwrap().as_str().to_string();
                let value = parse_expr(inner.next().unwrap());
                policy_file.defines.push((name, value));
            }
            Rule::policy => {
                policy_file.policies.push(parse_policy_block(pair));
            }
            Rule::use_stmt => {
                policy_file.use_stmt = Some(parse_use_stmt(pair));
            }
            Rule::EOI => {}
            _ => {}
        }
    }

    Ok(policy_file)
}

fn parse_policy_block(pair: pest::iterators::Pair<Rule>) -> Policy {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut entries = Vec::new();

    for item in inner {
        match item.as_rule() {
            Rule::action_block => {
                entries.push(PolicyEntry::ActionBlock(parse_action_block(item)));
            }
            Rule::use_ref => {
                let name_pair = item.into_inner().next().unwrap();
                let name_span = span_of(&name_pair);
                let policy_name = name_pair.as_str().to_string();
                entries.push(PolicyEntry::UseRef(policy_name, name_span));
            }
            _ => {}
        }
    }

    Policy { name, entries }
}

fn parse_action_block(pair: pest::iterators::Pair<Rule>) -> ActionBlock {
    let mut inner = pair.into_inner();
    let action = parse_action(inner.next().unwrap());
    let rules_pair = inner.next().unwrap();
    let rules = rules_pair.into_inner().map(parse_syscall_entry).collect();
    ActionBlock { action, rules }
}

fn parse_action(pair: pest::iterators::Pair<Rule>) -> Action {
    // For plain keywords (ALLOW, KILL, etc.), into_inner() may be empty —
    // the action rule matched the keyword directly. For parameterized
    // actions (ERRNO(n), TRAP(n)), there's a child rule.
    if let Some(inner) = pair.clone().into_inner().next() {
        match inner.as_rule() {
            Rule::errno_action => {
                let expr = parse_expr(inner.into_inner().next().unwrap());
                return Action::Errno(expr);
            }
            Rule::trap_action => {
                let expr = parse_expr(inner.into_inner().next().unwrap());
                return Action::Trap(expr);
            }
            Rule::trace_action => {
                let expr = parse_expr(inner.into_inner().next().unwrap());
                return Action::Trace(expr);
            }
            _ => {}
        }
    }
    // Plain keyword — match on the text
    let text = pair.as_str().trim();
    match text {
        "ALLOW" => Action::Allow,
        "KILL" => Action::Kill,
        "KILL_PROCESS" => Action::KillProcess,
        "LOG" => Action::Log,
        "USER_NOTIF" => Action::UserNotif,
        other => panic!("unknown action: {other}"),
    }
}

fn parse_syscall_entry(pair: pest::iterators::Pair<Rule>) -> SyscallRule {
    let mut inner = pair.into_inner();
    let name_pair = inner.next().unwrap();
    let name_span = span_of(&name_pair);
    let name = name_pair.as_str().to_string();
    let mut args = Vec::new();
    let mut filter = None;

    for item in inner {
        match item.as_rule() {
            Rule::arg_decl => {
                args = item.into_inner().map(|p| p.as_str().to_string()).collect();
            }
            Rule::filter_block => {
                filter = Some(parse_bool_expr(item.into_inner().next().unwrap()));
            }
            _ => {}
        }
    }

    SyscallRule {
        name,
        name_span,
        args,
        filter,
    }
}

fn parse_bool_expr(pair: pest::iterators::Pair<Rule>) -> BoolExpr {
    // bool_expr = or_expr ("," or_expr)*
    let mut inner = pair.into_inner();
    let mut result = parse_or_expr(inner.next().unwrap());
    for next in inner {
        result = BoolExpr::Or(Box::new(result), Box::new(parse_or_expr(next)));
    }
    result
}

fn parse_or_expr(pair: pest::iterators::Pair<Rule>) -> BoolExpr {
    let mut inner = pair.into_inner();
    let mut result = parse_and_expr(inner.next().unwrap());
    for next in inner {
        result = BoolExpr::Or(Box::new(result), Box::new(parse_and_expr(next)));
    }
    result
}

fn parse_and_expr(pair: pest::iterators::Pair<Rule>) -> BoolExpr {
    let mut inner = pair.into_inner();
    let mut result = parse_not_expr(inner.next().unwrap());
    for next in inner {
        result = BoolExpr::And(Box::new(result), Box::new(parse_not_expr(next)));
    }
    result
}

fn parse_not_expr(pair: pest::iterators::Pair<Rule>) -> BoolExpr {
    let inner: Vec<_> = pair.into_inner().collect();
    if inner.len() == 1 {
        // Either a primary_expr or a negated not_expr
        let child = inner.into_iter().next().unwrap();
        match child.as_rule() {
            Rule::not_expr => BoolExpr::Not(Box::new(parse_not_expr(child))),
            Rule::primary_expr => parse_primary_expr(child),
            _ => unreachable!(),
        }
    } else {
        unreachable!()
    }
}

fn parse_primary_expr(pair: pest::iterators::Pair<Rule>) -> BoolExpr {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::bool_expr => parse_bool_expr(inner),
        Rule::comparison => parse_comparison(inner),
        _ => unreachable!(),
    }
}

fn parse_comparison(pair: pest::iterators::Pair<Rule>) -> BoolExpr {
    let mut inner = pair.into_inner();
    let lhs = parse_cmp_lhs(inner.next().unwrap());
    let op = parse_cmp_op(inner.next().unwrap());
    let rhs_pair = inner.next().unwrap();
    // cmp_rhs wraps expr
    let rhs = parse_expr(rhs_pair.into_inner().next().unwrap());
    BoolExpr::Compare(lhs, op, rhs)
}

fn parse_cmp_lhs(pair: pest::iterators::Pair<Rule>) -> CmpLhs {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::masked_expr => {
            let mut parts = inner.into_inner();
            let name_pair = parts.next().unwrap();
            let name_span = span_of(&name_pair);
            let name = name_pair.as_str().to_string();
            let mask = parse_expr(parts.next().unwrap());
            CmpLhs::Masked(name, name_span, mask)
        }
        Rule::ident => {
            let name_span = span_of(&inner);
            CmpLhs::Arg(inner.as_str().to_string(), name_span)
        }
        other => unreachable!("unexpected cmp_lhs child: {:?}", other),
    }
}

fn parse_cmp_op(pair: pest::iterators::Pair<Rule>) -> CmpOp {
    match pair.as_str() {
        "==" => CmpOp::Eq,
        "!=" => CmpOp::Ne,
        "<" => CmpOp::Lt,
        "<=" => CmpOp::Le,
        ">" => CmpOp::Gt,
        ">=" => CmpOp::Ge,
        other => panic!("unknown comparison operator: {other}"),
    }
}

fn parse_expr(pair: pest::iterators::Pair<Rule>) -> Expr {
    let atoms: Vec<_> = pair.into_inner().map(parse_expr_atom).collect();
    if atoms.len() == 1 {
        atoms.into_iter().next().unwrap()
    } else {
        Expr::BitOr(atoms)
    }
}

fn parse_expr_atom(pair: pest::iterators::Pair<Rule>) -> Expr {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::number => Expr::Number(parse_number(inner.as_str())),
        Rule::ident => {
            let span = span_of(&inner);
            Expr::Ident(inner.as_str().to_string(), span)
        }
        Rule::expr => parse_expr(inner),
        _ => unreachable!("unexpected atom child: {:?}", inner.as_rule()),
    }
}

fn parse_number(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .unwrap_or_else(|_| panic!("numeric literal overflows u64: {s}"))
    } else if let Some(oct) = s.strip_prefix("0o") {
        u64::from_str_radix(oct, 8).unwrap_or_else(|_| panic!("numeric literal overflows u64: {s}"))
    } else {
        s.parse()
            .unwrap_or_else(|_| panic!("numeric literal overflows u64: {s}"))
    }
}

fn parse_use_stmt(pair: pest::iterators::Pair<Rule>) -> UseStmt {
    let mut inner = pair.into_inner();
    let mut policies = Vec::new();

    // Collect policy names until we hit the action
    loop {
        let next = inner.next().unwrap();
        match next.as_rule() {
            Rule::ident => {
                let span = span_of(&next);
                policies.push((next.as_str().to_string(), span));
            }
            Rule::action => {
                return UseStmt {
                    policies,
                    default_action: parse_action(next),
                };
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_policy() {
        let input = r#"
            POLICY test {
                ALLOW { read, write, close }
                KILL { ptrace }
            }
            USE test DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        assert_eq!(pf.policies.len(), 1);
        assert_eq!(pf.policies[0].name, "test");
        assert!(pf.use_stmt.is_some());
    }

    #[test]
    fn parse_documented_example_counts() {
        let input = r#"
            #define STDOUT 1
            #define STDERR 2

            POLICY stdio {
                ALLOW {
                    read(fd, buf, count) { fd == 0 },
                    write(fd, buf, count) { fd == STDOUT || fd == STDERR },
                    close, dup, dup2, fstat,
                }
            }

            POLICY deny_dangerous {
                KILL { ptrace, process_vm_readv, process_vm_writev }
                ERRNO(1) { execve, execveat }
            }

            USE stdio, deny_dangerous DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        assert_eq!(pf.define_count(), 2);
        assert_eq!(pf.policy_count(), 2);
        assert!(pf.has_use_stmt());
    }

    #[test]
    fn parse_argument_filter() {
        let input = r#"
            POLICY stdio {
                ALLOW {
                    write(fd, buf, count) {
                        fd == 1 || fd == 2
                    }
                }
            }
            USE stdio DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        let policy = &pf.policies[0];
        if let PolicyEntry::ActionBlock(ab) = &policy.entries[0] {
            assert_eq!(ab.rules[0].name, "write");
            assert_eq!(ab.rules[0].args, vec!["fd", "buf", "count"]);
            assert!(ab.rules[0].filter.is_some());
        } else {
            panic!("expected action block");
        }
    }

    #[test]
    fn parse_defines_and_constants() {
        let input = r#"
            #define STDOUT 1
            #define STDERR 2

            POLICY test {
                ALLOW {
                    write(fd, buf, count) { fd == STDOUT || fd == STDERR }
                }
            }
            USE test DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        assert_eq!(pf.defines.len(), 2);
        assert_eq!(pf.defines[0].0, "STDOUT");
    }

    #[test]
    fn parse_errno_action() {
        let input = r#"
            #define EPERM 1
            POLICY test {
                ERRNO(1337) { geteuid }
                ERRNO(EPERM) { ptrace, sched_setaffinity }
            }
            USE test DEFAULT ALLOW
        "#;
        let pf = parse_policy(input).unwrap();
        if let PolicyEntry::ActionBlock(ab) = &pf.policies[0].entries[0] {
            match &ab.action {
                Action::Errno(Expr::Number(n)) => assert_eq!(*n, 1337),
                _ => panic!("expected ERRNO action"),
            }
        }
        if let PolicyEntry::ActionBlock(ab) = &pf.policies[0].entries[1] {
            match &ab.action {
                Action::Errno(Expr::Ident(name, _)) => assert_eq!(name, "EPERM"),
                other => panic!("expected symbolic ERRNO action, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_masked_expression() {
        let input = r#"
            POLICY test {
                ALLOW {
                    mmap(addr, len, prot, flags, fd, offset) {
                        (prot & 0x4) == 0
                    }
                }
            }
            USE test DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        if let PolicyEntry::ActionBlock(ab) = &pf.policies[0].entries[0] {
            let rule = &ab.rules[0];
            assert_eq!(rule.name, "mmap");
            match rule.filter.as_ref().unwrap() {
                BoolExpr::Compare(CmpLhs::Masked(name, _, _mask), CmpOp::Eq, _) => {
                    assert_eq!(name, "prot");
                }
                other => panic!("expected masked comparison, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_bitwise_or_flags() {
        let input = r#"
            #define O_RDWR 2
            #define O_CREAT 64

            POLICY test {
                ALLOW {
                    open(path, flags, mode) {
                        flags == O_RDWR|O_CREAT
                    }
                }
            }
            USE test DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        if let PolicyEntry::ActionBlock(ab) = &pf.policies[0].entries[0] {
            let filter = ab.rules[0].filter.as_ref().unwrap();
            match filter {
                BoolExpr::Compare(_, CmpOp::Eq, Expr::BitOr(parts)) => {
                    assert_eq!(parts.len(), 2);
                }
                other => panic!("expected bitwise OR, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_parenthesized_bitwise_or_flags() {
        let input = r#"
            #define PROT_READ 1
            #define PROT_WRITE 2

            POLICY test {
                ALLOW {
                    mmap(addr, len, prot, flags, fd, offset) {
                        prot == (PROT_READ | PROT_WRITE)
                    }
                }
            }
            USE test DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        if let PolicyEntry::ActionBlock(ab) = &pf.policies[0].entries[0] {
            let filter = ab.rules[0].filter.as_ref().unwrap();
            match filter {
                BoolExpr::Compare(_, CmpOp::Eq, Expr::BitOr(parts)) => {
                    assert_eq!(parts.len(), 2);
                }
                other => panic!("expected parenthesized BitOr, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_policy_composition() {
        let input = r#"
            POLICY read_stdio {
                ALLOW { read(fd, buf, count) { fd == 0 } }
            }

            POLICY write_stdio {
                ALLOW {
                    write(fd, buf, count) { fd == 1, fd == 2 }
                }
            }

            POLICY main {
                USE read_stdio,
                USE write_stdio
            }

            USE main DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        assert_eq!(pf.policies.len(), 3);
        let main = &pf.policies[2];
        assert_eq!(main.name, "main");
        assert!(matches!(&main.entries[0], PolicyEntry::UseRef(n, _) if n == "read_stdio"));
        assert!(matches!(&main.entries[1], PolicyEntry::UseRef(n, _) if n == "write_stdio"));
    }

    #[test]
    fn parse_comments() {
        let input = r#"
            // This is a comment
            POLICY test {
                ALLOW {
                    read, /* inline comment */ write
                }
            }
            USE test DEFAULT ALLOW
        "#;
        let pf = parse_policy(input).unwrap();
        if let PolicyEntry::ActionBlock(ab) = &pf.policies[0].entries[0] {
            assert_eq!(ab.rules.len(), 2);
        }
    }

    #[test]
    fn parse_complex_boolean() {
        let input = r#"
            POLICY test {
                ALLOW {
                    write(fd, buf, count) {
                        (fd == 1 || fd == 2) && (count < 4096 || buf == 0)
                    }
                }
            }
            USE test DEFAULT KILL
        "#;
        let pf = parse_policy(input).unwrap();
        if let PolicyEntry::ActionBlock(ab) = &pf.policies[0].entries[0] {
            assert!(ab.rules[0].filter.is_some());
            // The filter should be And(Or(...), Or(...))
            match ab.rules[0].filter.as_ref().unwrap() {
                BoolExpr::And(_, _) => {}
                other => panic!("expected AND at top level, got {other:?}"),
            }
        }
    }
}
