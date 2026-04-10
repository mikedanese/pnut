use crate::ast::CmpOp;
use crate::error::Error;
use crate::resolve::Expr;

use super::{
    BPF_ALU_AND_K, BPF_JMP_JEQ_K, BPF_JMP_JGE_K, BPF_JMP_JGT_K, BPF_JMP_JSET_K, BPF_LD_W_ABS,
    OFFSET_ARGS,
};

/// A location in the reverse-emitted expression buffer.
pub(super) type Loc = i32;

/// Reverse-emission buffer for expression codegen.
///
/// Instructions are pushed in reverse order. `current_loc()` returns the index
/// of the last-emitted instruction. When the expression is complete, the buffer
/// is reversed and appended to the main instruction stream.
pub(super) struct ExprBuf {
    insns: Vec<libc::sock_filter>,
}

impl ExprBuf {
    pub(super) fn new() -> Self {
        ExprBuf { insns: Vec::new() }
    }

    /// Index of the last-emitted instruction (the "current location").
    pub(super) fn current_loc(&self) -> Loc {
        (self.insns.len() as Loc) - 1
    }

    /// Compute the forward jump distance from `from` to `to` in the
    /// reversed buffer.
    fn jump_offset(&self, from: Loc, to: Loc) -> Result<u8, Error> {
        if from <= to {
            return Err(Error::Codegen {
                message: format!("forward jump in reversed buffer: from={from} to={to}"),
                span: None,
            });
        }
        let offset = from - to - 1;
        if !(0..=255).contains(&offset) {
            return Err(Error::Codegen {
                message: format!(
                    "expression too complex: jump offset {offset} exceeds maximum 255"
                ),
                span: None,
            });
        }
        Ok(offset as u8)
    }

    /// Emit a BPF statement (no jumps) and return its location.
    pub(super) fn emit_stmt(&mut self, code: u16, k: u32) -> Loc {
        self.insns.push(libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        });
        self.current_loc()
    }

    /// Emit a BPF conditional jump with true/false locations.
    pub(super) fn emit_jump(
        &mut self,
        code: u16,
        k: u32,
        tloc: Loc,
        floc: Loc,
    ) -> Result<Loc, Error> {
        self.insns.push(libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        });
        let loc = self.current_loc();
        let jt = self.jump_offset(loc, tloc)?;
        let jf = self.jump_offset(loc, floc)?;
        self.insns[loc as usize].jt = jt;
        self.insns[loc as usize].jf = jf;
        Ok(loc)
    }

    /// Load a 32-bit word from a seccomp_data argument.
    pub(super) fn emit_arg_load(&mut self, arg_index: u8, high: bool) -> Loc {
        let offset = OFFSET_ARGS + (arg_index as u32) * 8 + if high { 4 } else { 0 };
        self.emit_stmt(BPF_LD_W_ABS, offset)
    }

    /// Reverse the buffer in place and return the instructions.
    pub(super) fn finish(mut self) -> Vec<libc::sock_filter> {
        self.insns.reverse();
        self.insns
    }
}

/// Returns true if a u64 value requires 64-bit (high word) handling.
fn needs_64bit(val: u64) -> bool {
    val > u32::MAX as u64
}

/// Generate BPF for an expression tree using kafel's generate_expr pattern.
pub(super) fn generate_expr(
    buf: &mut ExprBuf,
    expr: &Expr,
    tloc: Loc,
    floc: Loc,
) -> Result<Loc, Error> {
    match expr {
        Expr::BoolConst(true) => Ok(tloc),
        Expr::BoolConst(false) => Ok(floc),
        Expr::And(left, right) => {
            let right_entry = generate_expr(buf, right, tloc, floc)?;
            generate_expr(buf, left, right_entry, floc)
        }
        Expr::Or(left, right) => {
            let right_entry = generate_expr(buf, right, tloc, floc)?;
            generate_expr(buf, left, tloc, right_entry)
        }
        Expr::Not(inner) => generate_expr(buf, inner, floc, tloc),
        Expr::Compare(lhs, op, rhs) => generate_comparison(buf, lhs, *op, rhs, tloc, floc),
        Expr::MaskedCompare {
            arg_index,
            mask,
            op,
            rhs,
        } => generate_masked_compare(buf, *arg_index, mask, *op, rhs, tloc, floc),
        Expr::Constant(v) => Ok(if *v != 0 { tloc } else { floc }),
        Expr::Arg(_) | Expr::BitOr(_) => Ok(tloc),
    }
}

fn generate_comparison(
    buf: &mut ExprBuf,
    lhs: &Expr,
    op: CmpOp,
    rhs: &Expr,
    tloc: Loc,
    floc: Loc,
) -> Result<Loc, Error> {
    if let (Some(lval), Some(rval)) = (const_value(lhs), const_value(rhs)) {
        return Ok(if evaluate_cmp(op, lval, rval) {
            tloc
        } else {
            floc
        });
    }

    let (bpf_type, effective_tloc, effective_floc) = match op {
        CmpOp::Eq => (BPF_JMP_JEQ_K, tloc, floc),
        CmpOp::Ne => (BPF_JMP_JEQ_K, floc, tloc),
        CmpOp::Gt => (BPF_JMP_JGT_K, tloc, floc),
        CmpOp::Ge => (BPF_JMP_JGE_K, tloc, floc),
        CmpOp::Lt => (BPF_JMP_JGE_K, floc, tloc),
        CmpOp::Le => (BPF_JMP_JGT_K, floc, tloc),
    };

    let arg_index = match lhs {
        Expr::Arg(idx) => *idx,
        Expr::Constant(_) => {
            if let Expr::Arg(idx) = rhs {
                return generate_comparison_swapped(buf, *idx, op, lhs, tloc, floc);
            }
            return Err(Error::Codegen {
                message: "both operands are constant but not folded".into(),
                span: None,
            });
        }
        _ => return Ok(floc),
    };

    match const_value(rhs) {
        Some(val) if !needs_64bit(val) => generate_cmp32_const(
            buf,
            bpf_type,
            arg_index,
            val as u32,
            effective_tloc,
            effective_floc,
        ),
        Some(val) => {
            let hi = (val >> 32) as u32;
            let lo = val as u32;
            match op {
                CmpOp::Eq => generate_equality_64(buf, arg_index, hi, lo, tloc, floc),
                CmpOp::Ne => generate_equality_64(buf, arg_index, hi, lo, floc, tloc),
                CmpOp::Gt | CmpOp::Ge => generate_inequality_64(
                    buf,
                    bpf_type,
                    arg_index,
                    hi,
                    lo,
                    effective_tloc,
                    effective_floc,
                ),
                CmpOp::Lt => generate_inequality_64(
                    buf,
                    BPF_JMP_JGE_K,
                    arg_index,
                    hi,
                    lo,
                    effective_tloc,
                    effective_floc,
                ),
                CmpOp::Le => generate_inequality_64(
                    buf,
                    BPF_JMP_JGT_K,
                    arg_index,
                    hi,
                    lo,
                    effective_tloc,
                    effective_floc,
                ),
            }
        }
        None => Ok(floc),
    }
}

fn generate_comparison_swapped(
    buf: &mut ExprBuf,
    arg_index: u8,
    op: CmpOp,
    const_expr: &Expr,
    tloc: Loc,
    floc: Loc,
) -> Result<Loc, Error> {
    let reversed_op = match op {
        CmpOp::Eq => CmpOp::Eq,
        CmpOp::Ne => CmpOp::Ne,
        CmpOp::Gt => CmpOp::Lt,
        CmpOp::Ge => CmpOp::Le,
        CmpOp::Lt => CmpOp::Gt,
        CmpOp::Le => CmpOp::Ge,
    };
    let arg_expr = Expr::Arg(arg_index);
    generate_comparison(buf, &arg_expr, reversed_op, const_expr, tloc, floc)
}

fn generate_cmp32_const(
    buf: &mut ExprBuf,
    bpf_type: u16,
    arg_index: u8,
    val: u32,
    tloc: Loc,
    floc: Loc,
) -> Result<Loc, Error> {
    buf.emit_jump(bpf_type, val, tloc, floc)?;
    buf.emit_arg_load(arg_index, false);
    Ok(buf.current_loc())
}

fn generate_equality_64(
    buf: &mut ExprBuf,
    arg_index: u8,
    hi: u32,
    lo: u32,
    tloc: Loc,
    floc: Loc,
) -> Result<Loc, Error> {
    buf.emit_jump(BPF_JMP_JEQ_K, lo, tloc, floc)?;
    buf.emit_arg_load(arg_index, false);
    let lo_entry = buf.current_loc();

    buf.emit_jump(BPF_JMP_JEQ_K, hi, lo_entry, floc)?;
    buf.emit_arg_load(arg_index, true);
    Ok(buf.current_loc())
}

fn generate_inequality_64(
    buf: &mut ExprBuf,
    bpf_type: u16,
    arg_index: u8,
    hi: u32,
    lo: u32,
    tloc: Loc,
    floc: Loc,
) -> Result<Loc, Error> {
    buf.emit_jump(bpf_type, lo, tloc, floc)?;
    buf.emit_arg_load(arg_index, false);
    let lo_entry = buf.current_loc();

    buf.emit_jump(BPF_JMP_JGE_K, hi, lo_entry, floc)?;
    let hi_ge_entry = buf.current_loc();
    buf.emit_jump(BPF_JMP_JGT_K, hi, tloc, hi_ge_entry)?;
    buf.emit_arg_load(arg_index, true);
    Ok(buf.current_loc())
}

fn generate_masked_compare(
    buf: &mut ExprBuf,
    arg_index: u8,
    mask: &Expr,
    op: CmpOp,
    rhs: &Expr,
    tloc: Loc,
    floc: Loc,
) -> Result<Loc, Error> {
    let mask_val = const_value(mask).ok_or_else(|| Error::Codegen {
        message: "masked comparison mask is not a constant".into(),
        span: None,
    })?;
    let rhs_val = const_value(rhs).ok_or_else(|| Error::Codegen {
        message: "masked comparison RHS is not a constant".into(),
        span: None,
    })?;

    if rhs_val == 0 && (op == CmpOp::Eq || op == CmpOp::Ne) && !needs_64bit(mask_val) {
        let (jset_tloc, jset_floc) = if op == CmpOp::Eq {
            (floc, tloc)
        } else {
            (tloc, floc)
        };
        buf.emit_jump(BPF_JMP_JSET_K, mask_val as u32, jset_tloc, jset_floc)?;
        buf.emit_arg_load(arg_index, false);
        return Ok(buf.current_loc());
    }

    if !needs_64bit(mask_val) && !needs_64bit(rhs_val) {
        let (bpf_type, effective_tloc, effective_floc) = match op {
            CmpOp::Eq => (BPF_JMP_JEQ_K, tloc, floc),
            CmpOp::Ne => (BPF_JMP_JEQ_K, floc, tloc),
            CmpOp::Gt => (BPF_JMP_JGT_K, tloc, floc),
            CmpOp::Ge => (BPF_JMP_JGE_K, tloc, floc),
            CmpOp::Lt => (BPF_JMP_JGE_K, floc, tloc),
            CmpOp::Le => (BPF_JMP_JGT_K, floc, tloc),
        };
        buf.emit_jump(bpf_type, rhs_val as u32, effective_tloc, effective_floc)?;
        buf.emit_stmt(BPF_ALU_AND_K, mask_val as u32);
        buf.emit_arg_load(arg_index, false);
        return Ok(buf.current_loc());
    }

    Ok(floc)
}

fn const_value(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Constant(v) => Some(*v),
        _ => None,
    }
}

fn evaluate_cmp(op: CmpOp, lhs: u64, rhs: u64) -> bool {
    match op {
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
        CmpOp::Lt => lhs < rhs,
        CmpOp::Le => lhs <= rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::Ge => lhs >= rhs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::BPF_RET_K;

    #[test]
    fn constant_comparison_short_circuits() {
        let mut buf = ExprBuf::new();
        let false_exit = buf.emit_stmt(BPF_RET_K, 0);
        let true_exit = buf.emit_stmt(BPF_RET_K, 1);
        let expr = Expr::Compare(
            Box::new(Expr::Constant(1)),
            CmpOp::Eq,
            Box::new(Expr::Constant(1)),
        );
        let entry = generate_expr(&mut buf, &expr, true_exit, false_exit).unwrap();
        assert_eq!(entry, true_exit);
        assert_eq!(buf.finish().len(), 2);
    }

    #[test]
    fn arg_comparison_emits_load_then_jump() {
        let mut buf = ExprBuf::new();
        let false_exit = buf.emit_stmt(BPF_RET_K, 0);
        let true_exit = buf.emit_stmt(BPF_RET_K, 1);
        let expr = Expr::Compare(
            Box::new(Expr::Arg(0)),
            CmpOp::Eq,
            Box::new(Expr::Constant(42)),
        );
        generate_expr(&mut buf, &expr, true_exit, false_exit).unwrap();
        let insns = buf.finish();
        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].code, BPF_LD_W_ABS);
        assert_eq!(insns[0].k, OFFSET_ARGS);
        assert_eq!(insns[1].code, BPF_JMP_JEQ_K);
        assert_eq!(insns[1].k, 42);
    }

    #[test]
    fn jset_path_skips_and_instruction() {
        let mut buf = ExprBuf::new();
        let false_exit = buf.emit_stmt(BPF_RET_K, 0);
        let true_exit = buf.emit_stmt(BPF_RET_K, 1);
        let expr = Expr::MaskedCompare {
            arg_index: 1,
            mask: Box::new(Expr::Constant(0x4)),
            op: CmpOp::Eq,
            rhs: Box::new(Expr::Constant(0)),
        };
        generate_expr(&mut buf, &expr, true_exit, false_exit).unwrap();
        let insns = buf.finish();
        assert!(insns.iter().any(|insn| insn.code == BPF_JMP_JSET_K));
        assert!(!insns.iter().any(|insn| insn.code == BPF_ALU_AND_K));
    }

    #[test]
    fn high_word_load_is_emitted_for_64bit_constants() {
        let mut buf = ExprBuf::new();
        let false_exit = buf.emit_stmt(BPF_RET_K, 0);
        let true_exit = buf.emit_stmt(BPF_RET_K, 1);
        let expr = Expr::Compare(
            Box::new(Expr::Arg(0)),
            CmpOp::Eq,
            Box::new(Expr::Constant(0x1_0000_0001)),
        );
        generate_expr(&mut buf, &expr, true_exit, false_exit).unwrap();
        let insns = buf.finish();
        assert!(
            insns
                .iter()
                .any(|insn| insn.code == BPF_LD_W_ABS && insn.k == OFFSET_ARGS + 4)
        );
    }
}
