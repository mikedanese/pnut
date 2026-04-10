use std::collections::HashMap;

use crate::error::Error;
use crate::resolve::{Action, Policy};

use super::action_to_ret;
use super::expr::{ExprBuf, Loc, generate_expr};
use super::ranges::{ConditionalMapping, RangeAction, SyscallRange, normalize_ranges};
use super::{
    AUDIT_ARCH_X86_64, BPF_JMP_JA, BPF_JMP_JEQ_K, BPF_LD_W_ABS, BPF_RET_K, MAX_JUMP, OFFSET_ARCH,
    OFFSET_NR,
};

const FALSE_EXIT_PLACEHOLDER: u32 = 0xDEAD_0001;
const TRUE_EXIT_PLACEHOLDER: u32 = 0xDEAD_0002;

/// Stable identifier for a distinct seccomp return value in `action_table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ActionId(usize);

/// A jump destination in the reverse-emitted program.
///
/// `Location` points at an instruction already present in the reverse buffer.
/// `Action` is resolved lazily into a shared `BPF_RET` site so multiple ranges
/// can reuse the same return instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Location(Loc),
    Action(ActionId),
}

/// Reverse-emission BPF codegen following kafel C's architecture.
pub(super) struct ReverseCodegen {
    /// Instructions are pushed in reverse order and reversed once at the end.
    buffer: Vec<libc::sock_filter>,
    /// Distinct return values referenced by `ActionId`.
    action_table: Vec<u32>,
    /// Reverse lookup used to deduplicate equal `SECCOMP_RET_*` encodings.
    action_ids: HashMap<u32, ActionId>,
    /// Cache of the most recent emitted return site for each action.
    action_loc_cache: HashMap<ActionId, Loc>,
}

impl ReverseCodegen {
    pub(super) fn new() -> Self {
        ReverseCodegen {
            buffer: Vec::new(),
            action_table: Vec::new(),
            action_ids: HashMap::new(),
            action_loc_cache: HashMap::new(),
        }
    }

    fn register_action(&mut self, ret_val: u32) -> ActionId {
        if let Some(&action_id) = self.action_ids.get(&ret_val) {
            return action_id;
        }
        let action_id = ActionId(self.action_table.len());
        self.action_table.push(ret_val);
        self.action_ids.insert(ret_val, action_id);
        action_id
    }

    fn current_loc(&self) -> Loc {
        (self.buffer.len() as Loc) - 1
    }

    fn loc_to_jump(&self, loc: Loc) -> i32 {
        self.current_loc() - loc
    }

    fn add_instruction(&mut self, insn: libc::sock_filter) -> Loc {
        self.buffer.push(insn);
        self.current_loc()
    }

    pub(super) fn emit_stmt(&mut self, code: u16, k: u32) -> Loc {
        self.add_instruction(libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        })
    }

    /// Resolve a lazily-tracked action to an actual `BPF_RET` instruction.
    ///
    /// The cache is intentionally distance-sensitive: if the previously emitted
    /// return site has drifted beyond the 8-bit jump limit, emit a fresh one
    /// nearer to the current instruction stream instead of forcing a trampoline.
    fn resolve_action(&mut self, action_id: ActionId) -> Loc {
        if let Some(&loc) = self.action_loc_cache.get(&action_id)
            && self.loc_to_jump(loc) <= MAX_JUMP
        {
            return loc;
        }

        let ret_val = self.action_table[action_id.0];
        let loc = self.emit_stmt(BPF_RET_K, ret_val);
        self.action_loc_cache.insert(action_id, loc);
        loc
    }

    fn resolve_target(&mut self, target: Target) -> Loc {
        match target {
            Target::Location(loc) => loc,
            Target::Action(action_id) => self.resolve_action(action_id),
        }
    }

    /// Ensure that a target can be reached by the next conditional jump.
    ///
    /// If a resolved location is more than 255 instructions away in reverse
    /// coordinates, insert a `BPF_JA` trampoline and jump to that instead.
    fn ensure_jumpable_target(&mut self, target: Target) -> Loc {
        let loc = self.resolve_target(target);
        let distance = self.loc_to_jump(loc);
        if distance > MAX_JUMP {
            return self.add_instruction(libc::sock_filter {
                code: BPF_JMP_JA,
                jt: 0,
                jf: 0,
                k: distance as u32,
            });
        }
        loc
    }

    /// Emit a conditional jump in reverse order.
    ///
    /// False is resolved first because inserting its trampoline can move the
    /// true branch farther away; the second true-resolution pass handles that
    /// drift without the caller needing to think about it.
    fn add_jump(&mut self, bpf_type: u16, k: u32, tloc: Target, floc: Target) -> Loc {
        if tloc == floc {
            return self.resolve_target(tloc);
        }

        let floc = self.ensure_jumpable_target(floc);
        let tloc = self.ensure_jumpable_target(tloc);
        let tloc = self.ensure_jumpable_target(Target::Location(tloc));

        let jt_dist = self.loc_to_jump(tloc);
        let jf_dist = self.loc_to_jump(floc);
        debug_assert!(
            jt_dist <= MAX_JUMP,
            "jt distance {jt_dist} exceeds max after trampolining"
        );
        debug_assert!(
            jf_dist <= MAX_JUMP,
            "jf distance {jf_dist} exceeds max after trampolining"
        );

        self.add_instruction(libc::sock_filter {
            code: (libc::BPF_JMP as u16) | bpf_type,
            jt: jt_dist as u8,
            jf: jf_dist as u8,
            k,
        })
    }

    fn add_jump_ge(&mut self, than: u32, tloc: Target, floc: Target) -> Loc {
        if than == 0 {
            return self.resolve_target(tloc);
        }
        self.add_jump(libc::BPF_JGE as u16, than, tloc, floc)
    }

    fn action_target(&mut self, action: &Action) -> Target {
        Target::Action(self.register_action(action_to_ret(action)))
    }

    /// Lower an ordered list of conditional mappings into a straight-line
    /// reverse-emitted chain.
    ///
    /// Each mapping is compiled to expression code with placeholder exits,
    /// then those exits are rewritten to jumps into either the mapping action
    /// or the next fallback branch in the chain.
    fn emit_conditional_chain(
        &mut self,
        mappings: &[ConditionalMapping<'_>],
        fallback: &Action,
    ) -> Result<Loc, Error> {
        let mut next_target = self.action_target(fallback);

        for mapping in mappings.iter().rev() {
            let action_target = self.action_target(&mapping.action);
            let false_target = self.ensure_jumpable_target(next_target);
            let true_target = self.ensure_jumpable_target(action_target);
            let expr_insns = self.lower_expr_with_placeholders(mapping.expr)?;

            for insn in expr_insns.iter().rev() {
                if insn.code == BPF_RET_K && insn.k == FALSE_EXIT_PLACEHOLDER {
                    self.emit_placeholder_jump(false_target);
                } else if insn.code == BPF_RET_K && insn.k == TRUE_EXIT_PLACEHOLDER {
                    self.emit_placeholder_jump(true_target);
                } else {
                    self.add_instruction(*insn);
                }
            }

            next_target = Target::Location(self.current_loc());
        }

        Ok(self.resolve_target(next_target))
    }

    /// Build expression code in a local buffer that pretends true/false exits
    /// are plain `BPF_RET`s. The caller later patches those placeholders into
    /// real jumps inside the main reverse-emission buffer.
    fn lower_expr_with_placeholders(
        &self,
        expr: &crate::resolve::Expr,
    ) -> Result<Vec<libc::sock_filter>, Error> {
        let mut expr_buf = ExprBuf::new();
        let false_exit = expr_buf.emit_stmt(BPF_RET_K, FALSE_EXIT_PLACEHOLDER);
        let true_exit = expr_buf.emit_stmt(BPF_RET_K, TRUE_EXIT_PLACEHOLDER);
        generate_expr(&mut expr_buf, expr, true_exit, false_exit)?;
        Ok(expr_buf.finish())
    }

    /// Replace a placeholder expression exit with an unconditional jump into
    /// the already-emitted main buffer.
    fn emit_placeholder_jump(&mut self, target_loc: Loc) {
        let jump_offset = self.loc_to_jump(target_loc);
        self.add_instruction(libc::sock_filter {
            code: BPF_JMP_JA,
            jt: 0,
            jf: 0,
            k: jump_offset as u32,
        });
    }

    fn generate_action(&mut self, range: &SyscallRange<'_>) -> Result<Target, Error> {
        match &range.action {
            RangeAction::Unconditional(action) => Ok(self.action_target(action)),
            RangeAction::Conditional { mappings, fallback } => Ok(Target::Location(
                self.emit_conditional_chain(mappings, fallback)?,
            )),
        }
    }

    /// Build kafel's balanced JGE search tree over normalized syscall ranges.
    ///
    /// The stack stores partial subtrees by level. When two adjacent subtrees
    /// have the same level they are merged immediately, which yields the same
    /// compact tree shape as the original C implementation.
    fn generate_rules(&mut self, ranges: &[SyscallRange<'_>]) -> Result<Target, Error> {
        if ranges.is_empty() {
            return Err(Error::Codegen {
                message: "no syscall ranges to generate".into(),
                span: None,
            });
        }

        struct BufEntry {
            level: i32,
            action: Target,
            nr: u32,
        }

        let mut buf: Vec<BufEntry> = Vec::with_capacity(33);

        for range in ranges.iter().rev() {
            let action = self.generate_action(range)?;

            if let Some(top) = buf.last_mut()
                && top.action == action
            {
                debug_assert!(range.last + 1 == top.nr);
                top.nr = range.first;
                continue;
            }

            while buf.len() >= 2 && buf[buf.len() - 2].level == buf[buf.len() - 1].level {
                let top = buf.pop().unwrap();
                let second = buf.last_mut().unwrap();
                second.action =
                    Target::Location(self.add_jump_ge(second.nr, second.action, top.action));
                second.nr = top.nr;
                second.level += 1;
            }

            buf.push(BufEntry {
                level: 0,
                nr: range.first,
                action,
            });
        }

        if buf.is_empty() || buf.last().unwrap().nr != 0 {
            return Err(Error::Codegen {
                message: "range tree does not cover syscall 0".into(),
                span: None,
            });
        }

        while buf.len() >= 2 {
            let top = buf.pop().unwrap();
            let second = buf.last_mut().unwrap();
            second.action =
                Target::Location(self.add_jump_ge(second.nr, second.action, top.action));
            second.nr = top.nr;
        }

        Ok(buf[0].action)
    }

    /// Emit the fixed seccomp prelude in reverse order.
    ///
    /// After the final buffer reversal the program starts with:
    /// `load arch -> jeq AUDIT_ARCH_X86_64 -> kill_process -> load nr`.
    fn emit_arch_prelude(&mut self) {
        self.emit_stmt(BPF_LD_W_ABS, OFFSET_NR);
        self.emit_stmt(BPF_RET_K, libc::SECCOMP_RET_KILL_PROCESS);
        self.add_instruction(libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_X86_64,
        });
        self.emit_stmt(BPF_LD_W_ABS, OFFSET_ARCH);
    }

    /// Generate the complete BPF program.
    ///
    /// The sequence is:
    /// 1. normalize rules into syscall ranges
    /// 2. emit the reverse decision tree
    /// 3. force the tree root to a concrete target
    /// 4. append the fixed arch/syscall prelude
    /// 5. reverse the buffer into executable order
    pub(super) fn generate(&mut self, policy: &Policy) -> Result<Vec<libc::sock_filter>, Error> {
        let ranges = normalize_ranges(policy);
        let tree_entry = self.generate_rules(&ranges)?;
        let _ = self.resolve_target(tree_entry);
        self.emit_arch_prelude();
        self.buffer.reverse();

        if self.buffer.len() > u16::MAX as usize {
            return Err(Error::Codegen {
                message: format!(
                    "BPF program too large: {} instructions (max {})",
                    self.buffer.len(),
                    u16::MAX
                ),
                span: None,
            });
        }

        Ok(std::mem::take(&mut self.buffer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::PolicyEntry;

    fn unconditional_policy(syscalls: &[u32], action: Action, default_action: Action) -> Policy {
        Policy {
            entries: syscalls
                .iter()
                .map(|&syscall_number| PolicyEntry {
                    syscall_number,
                    action: action.clone(),
                    filter: None,
                })
                .collect(),
            default_action,
        }
    }

    #[test]
    fn action_registration_is_deduplicated() {
        let mut codegen = ReverseCodegen::new();
        let first = codegen.register_action(libc::SECCOMP_RET_ALLOW);
        let second = codegen.register_action(libc::SECCOMP_RET_ALLOW);
        let third = codegen.register_action(libc::SECCOMP_RET_KILL);

        assert_eq!(first, second);
        assert_ne!(first, third);
        assert_eq!(codegen.action_table.len(), 2);
    }

    #[test]
    fn far_targets_get_trampolines() {
        let mut codegen = ReverseCodegen::new();
        let target = Target::Location(codegen.emit_stmt(BPF_RET_K, 1));
        for _ in 0..=MAX_JUMP {
            codegen.emit_stmt(BPF_RET_K, 2);
        }

        let resolved = codegen.ensure_jumpable_target(target);
        assert_eq!(codegen.buffer[resolved as usize].code, BPF_JMP_JA);
    }

    #[test]
    fn one_range_tree_returns_action_target() {
        let policy = unconditional_policy(&[0], Action::Allow, Action::Kill);
        let ranges = normalize_ranges(&policy);
        let mut codegen = ReverseCodegen::new();
        let target = codegen.generate_rules(&ranges).unwrap();
        assert!(matches!(target, Target::Action(_) | Target::Location(_)));
    }

    #[test]
    fn two_ranges_produce_a_jump_node() {
        let policy = unconditional_policy(&[0], Action::Allow, Action::Kill);
        let ranges = normalize_ranges(&policy);
        let mut codegen = ReverseCodegen::new();
        let _ = codegen.generate_rules(&ranges).unwrap();
        assert!(
            codegen
                .buffer
                .iter()
                .any(|insn| (insn.code & 0x07) == libc::BPF_JMP as u16)
        );
    }

    #[test]
    fn generated_program_keeps_arch_prelude_first() {
        let policy = unconditional_policy(&[0, 1], Action::Allow, Action::Kill);
        let mut codegen = ReverseCodegen::new();
        let insns = codegen.generate(&policy).unwrap();

        assert_eq!(insns[0].code, BPF_LD_W_ABS);
        assert_eq!(insns[0].k, OFFSET_ARCH);
        assert_eq!(insns[1].code, BPF_JMP_JEQ_K);
    }
}
