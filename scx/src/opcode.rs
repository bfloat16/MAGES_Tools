use crate::expr::*;
use crate::format::*;
use crate::il::*;
use crate::scx::ScxFile;

// ── opcode state ──

struct St<'a> {
    scx: &'a ScxFile,
    data: &'a [u8],
    offset: usize,
    max: usize,
    opcode_id: u8,
    opcode_name: String,
    p: usize,
}

impl<'a> St<'a> {
    fn new(scx: &'a ScxFile, offset: usize, max: usize) -> Self {
        let major = scx.data[offset] & 0x7F;
        let index = scx.data[offset + 1];
        Self {
            scx,
            data: &scx.data,
            offset,
            max,
            opcode_id: index,
            opcode_name: format!("OP_{major:02X}{index:02X}"),
            p: offset + 2,
        }
    }

    fn byte(&mut self) -> Option<u8> {
        if self.p >= self.max {
            None
        } else {
            let b = self.data[self.p];
            self.p += 1;
            Some(b)
        }
    }

    fn expr(&mut self) -> ExprValue {
        let (e, next) = read_expr_value(self.data, self.p, self.max);
        self.p = next;
        e
    }

    fn u16_val(&mut self) -> Option<u16> {
        let (v, next) = decode_u16(self.data, self.p, self.max);
        self.p = next;
        v
    }

    fn cstring(&mut self) -> String {
        let (s, next) = read_cstring(self.data, self.p, self.max);
        self.p = next;
        s
    }

    fn raw_bytes(&mut self, len: usize) -> String {
        let actual = len.min(self.max - self.p);
        let s = self.data[self.p..self.p + actual].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        self.p += actual;
        s
    }

    fn fin(&self, mnemonic: &str, ops: Vec<IlOperand>) -> IlInstruction {
        emit(self.offset, self.p, mnemonic, ops)
    }

    fn fin0(&self, mnemonic: &str) -> IlInstruction {
        emit(self.offset, self.p, mnemonic, vec![])
    }

    fn stub(&self) -> IlInstruction {
        self.fin0(&self.opcode_name.to_ascii_lowercase())
    }

    fn trunc(&self, mnemonic: &str) -> IlInstruction {
        self.fin(mnemonic, vec![n("trunc", "1")])
    }

    fn mode(&self, mnemonic: &str, m: u8) -> IlInstruction {
        self.fin(mnemonic, vec![n("mode", hex8(m))])
    }

    fn subcmd(&self, mnemonic: &str, sc: u8) -> IlInstruction {
        self.fin(mnemonic, vec![n("subcmd", hex8(sc))])
    }
}

// short helpers
fn n(name: &str, val: impl Into<String>) -> IlOperand {
    IlOperand::named(name, val)
}
fn ne(name: &str, val: ExprValue) -> IlOperand {
    IlOperand::named_expr(name, val)
}
fn pe(val: ExprValue) -> IlOperand {
    IlOperand::pos_expr(val)
}

pub fn decode_scx_known(scx: &ScxFile, offset: usize, limit: usize) -> IlInstruction {
    let data = &scx.data;
    let max = data.len().min(limit);
    let major = data[offset] & 0x7F;
    let index = data[offset + 1];
    let raw_id = ((major as u16) << 8) | index as u16;
    let mut s = St::new(scx, offset, max);

    let decoded = match major {
        0x00 => table00(&mut s),
        0x01 => table01(&mut s),
        0x10 => table10(&mut s),
        0x20 => table20(&mut s),
        _ => None,
    };

    if let Some(inst) = decoded {
        return inst;
    }

    let raw = data[offset..offset.min(max) + 16.min(max - offset)].iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    emit(offset, offset + 2, "unknown_operands", vec![n("op", format!("OP_{raw_id:04X}")), n("raw16", raw)])
}

// ── Table 00 ──

fn table00(s: &mut St) -> Option<IlInstruction> {
    Some(match s.opcode_id {
        0x00 => s.fin0("break_vm"),
        0x01 => {
            let Some(subcmd) = s.byte() else { return Some(s.trunc("call_context")) };
            let slot = s.expr();
            let script = s.expr();
            let Some(target) = s.u16_val() else {
                return Some(s.fin("call_context", vec![n("sub", hex8(subcmd)), ne("slot", slot), ne("script", script), n("trunc", "1")]));
            };
            if subcmd >= 0x80 {
                let name = s.cstring();
                s.fin("call_context", vec![n("sub", hex8(subcmd)), ne("slot", slot), ne("script", script), n("target", fmt_l0(target)), n("name", format!("\"{name}\""))])
            } else {
                s.fin("call_context", vec![n("sub", hex8(subcmd)), ne("slot", slot), ne("script", script), n("target", fmt_l0(target))])
            }
        }
        0x02 => {
            let e = s.expr();
            s.fin("free_context_by_expr", vec![pe(e)])
        }
        0x03 => s.fin0("set_stop_flag"),
        0x04 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("load_script_async")) };
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("load_script_async", vec![n("mode", hex8(mode)), pe(a0), pe(a1)])
        }
        0x05 => {
            let e = s.expr();
            s.fin("wait_expr", vec![pe(e)])
        }
        0x06 => s.fin0("set_ctx_flag_and_break"),
        0x07 => {
            let Some(t) = s.u16_val() else { return Some(s.trunc("jmp_table0")) };
            s.fin("jmp_table0", vec![n("target", fmt_l0(t))])
        }
        0x08 => {
            let sel = s.expr();
            let Some(tb) = s.u16_val() else { return Some(s.fin("switch_jmp", vec![ne("selector", sel), n("trunc", "1")])) };
            if let Some(imm) = sel.try_get_immediate() {
                if imm >= 0 && (tb as usize) < s.scx.table0.len() {
                    let base_off = s.scx.table0[tb as usize] as usize;
                    let case_off = base_off + imm as usize * 2;
                    if case_off + 2 <= s.max.min(s.data.len()) {
                        let cl = read_u16_le(s.data, case_off);
                        return Some(s.fin("switch_jmp", vec![ne("selector", sel), n("table_base", fmt_l0(tb)), n("case_target", fmt_l0(cl))]));
                    }
                }
            }
            s.fin("switch_jmp", vec![ne("selector", sel), n("table_base", fmt_l0(tb))])
        }
        0x09 => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x0A => {
            let Some(sense) = s.byte() else { return Some(s.trunc("jmp_if_expr")) };
            let cond = s.expr();
            let Some(t) = s.u16_val() else {
                return Some(s.fin("jmp_if_expr", vec![n("sense", hex8(sense)), pe(cond), n("trunc", "1")]));
            };
            s.fin("jmp_if_expr", vec![n("sense", hex8(sense)), pe(cond), n("target", fmt_l0(t))])
        }
        0x0B => {
            let Some(t) = s.u16_val() else { return Some(s.trunc("call_table0")) };
            let Some(ret) = s.u16_val() else { return Some(s.trunc("call_table0")) };
            s.fin("call_table0", vec![n("target", fmt_l0(t)), n("ret", fmt_l2(ret))])
        }
        0x0C => {
            let e = s.expr();
            let Some(a1) = s.u16_val() else { return Some(s.fin("op_000c", vec![ne("arg0", e), n("trunc", "1")])) };
            s.fin("op_000c", vec![ne("arg0", e), n("arg1", fmt_u16(a1))])
        }
        0x0D => {
            let script = s.expr();
            let Some(t) = s.u16_val() else { return Some(s.fin("call_script", vec![ne("script", script), n("trunc", "1")])) };
            let Some(ret) = s.u16_val() else { return Some(s.fin("call_script", vec![ne("script", script), n("trunc", "1")])) };
            s.fin("call_script", vec![ne("script", script), n("target", fmt_l0(t)), n("ret", fmt_l2(ret))])
        }
        0x0E => s.fin0("ret"),
        0x0F => {
            let Some(cid) = s.u16_val() else { return Some(s.trunc("loop_jmp")) };
            let Some(t) = s.u16_val() else { return Some(s.trunc("loop_jmp")) };
            let cnt = s.expr();
            s.fin("loop_jmp", vec![n("counter", fmt_u16(cid)), n("target", fmt_l0(t)), ne("count", cnt)])
        }
        0x10 => {
            let Some(sense) = s.byte() else { return Some(s.trunc("cmp_flag_jmp")) };
            let flag = s.expr();
            let Some(t) = s.u16_val() else {
                return Some(s.fin("cmp_flag_jmp", vec![n("state", hex8(sense)), pe(flag), n("trunc", "1")]));
            };
            s.fin("cmp_flag_jmp", vec![n("state", hex8(sense)), pe(flag), n("target", fmt_l0(t))])
        }
        0x11 => {
            let Some(sense) = s.byte() else { return Some(s.trunc("cmp_expr_break")) };
            let e = s.expr();
            s.fin("cmp_expr_break", vec![n("state", hex8(sense)), pe(e)])
        }
        0x12 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("flag_set")) };
            let a0 = s.expr();
            if mode != 0 {
                let a1 = s.expr();
                s.fin("flag_set", vec![n("mode", hex8(mode)), pe(a0), pe(a1)])
            } else {
                s.fin("flag_set", vec![n("mode", hex8(mode)), pe(a0)])
            }
        }
        0x13 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("flag_clear")) };
            let a0 = s.expr();
            if mode != 0 {
                let a1 = s.expr();
                s.fin("flag_clear", vec![n("mode", hex8(mode)), pe(a0), pe(a1)])
            } else {
                s.fin("flag_clear", vec![n("mode", hex8(mode)), pe(a0)])
            }
        }
        0x14 => {
            let src = s.expr();
            let dst = s.expr();
            s.fin("var_copy", vec![ne("src", src), ne("dst", dst)])
        }
        0x15 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("cond_jmp_adv")) };
            let a0 = s.expr();
            if mode < 0x0A {
                let a1 = s.expr();
                let Some(t) = s.u16_val() else {
                    return Some(s.fin("cond_jmp_adv", vec![n("mode", hex8(mode)), pe(a0), pe(a1), n("trunc", "1")]));
                };
                s.fin("cond_jmp_adv", vec![n("mode", hex8(mode)), pe(a0), pe(a1), n("target", fmt_l0(t))])
            } else {
                let Some(t) = s.u16_val() else { return Some(s.fin("cond_jmp_adv", vec![n("mode", hex8(mode)), pe(a0), n("trunc", "1")])) };
                s.fin("cond_jmp_adv", vec![n("mode", hex8(mode)), pe(a0), n("target", fmt_l0(t))])
            }
        }
        0x16 => {
            let Some(flags) = s.byte() else { return Some(s.trunc("op_0016")) };
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_0016", vec![n("flags", hex8(flags)), ne("arg0", a0), ne("arg1", a1)])
        }
        0x17 => {
            let Some(flags) = s.byte() else { return Some(s.trunc("op_0017")) };
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            s.fin("op_0017", vec![n("flags", hex8(flags)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
        }
        0x18 => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_0018", vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x19 => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_0019", vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x1A => s.fin0("op_001a"),
        0x1B => {
            let e = s.expr();
            s.fin("op_001b", vec![pe(e)])
        }
        0x1C => s.fin0("op_001c"),
        0x1D => {
            let e = s.expr();
            s.fin("expr_only", vec![pe(e)])
        }
        0x1E => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_001e")) };
            s.mode("op_001e", m)
        }
        0x1F => {
            let e = s.expr();
            s.fin("set_tmp", vec![pe(e)])
        }
        0x20 => {
            let e = s.expr();
            let Some(t) = s.u16_val() else { return Some(s.fin("jmp_if_tmp_eq", vec![pe(e), n("trunc", "1")])) };
            s.fin("jmp_if_tmp_eq", vec![pe(e), n("target", fmt_l0(t))])
        }
        0x21 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("op_0021")) };
            let a0 = s.expr();
            if mode == 2 {
                let a1 = s.expr();
                s.fin("op_0021", vec![n("mode", hex8(mode)), ne("arg0", a0), ne("arg1", a1)])
            } else {
                s.fin("op_0021", vec![n("mode", hex8(mode)), ne("arg0", a0)])
            }
        }
        0x22 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0022")) };
            s.mode("op_0022", m)
        }
        0x23 => {
            if s.p + 1 >= s.max {
                return Some(s.trunc("op_0023"));
            }
            let slot = s.byte().unwrap();
            let mode = s.byte().unwrap();
            if mode != 2 {
                let val = s.expr();
                let aux = s.expr();
                s.fin("op_0023", vec![n("slot", hex8(slot)), n("mode", hex8(mode)), ne("value", val), ne("aux", aux)])
            } else {
                s.fin("op_0023", vec![n("slot", hex8(slot)), n("mode", hex8(mode))])
            }
        }
        0x24 => {
            let Some(sel) = s.byte() else { return Some(s.trunc("op_0024")) };
            s.fin("op_0024", vec![n("selector", hex8(sel))])
        }
        0x25 => {
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            s.fin("op_0025", vec![ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
        }
        0x26 => {
            let a0 = s.expr();
            s.fin("op_0026", vec![ne("arg0", a0)])
        }
        0x27 => s.fin0("op_0027"),
        0x28 => {
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            let a3 = s.expr();
            s.fin("op_0028", vec![ne("arg0", a0), ne("arg1", a1), ne("arg2", a2), ne("arg3", a3)])
        }
        0x29 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0029")) };
            s.mode("op_0029", m)
        }
        0x2A => {
            let Some(sc) = s.byte() else { return Some(s.trunc("op_002a")) };
            s.subcmd("op_002a", sc)
        }
        0x2B => {
            let a0 = s.expr();
            s.fin("op_002b", vec![ne("arg0", a0)])
        }
        0x2C => {
            let a0 = s.expr();
            s.fin("op_002c", vec![ne("arg0", a0)])
        }
        0x2D => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_002d")) };
            s.mode("op_002d", m)
        }
        0x2E => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_002e")) };
            let a0 = s.expr();
            s.fin("op_002e", vec![n("mode", hex8(m)), ne("arg0", a0)])
        }
        0x2F => {
            let Some(sc) = s.byte() else { return Some(s.trunc(&s.opcode_name.to_ascii_lowercase())) };
            let nm = s.opcode_name.to_ascii_lowercase();
            if matches!(sc, 1 | 2 | 0x10 | 0x11) {
                let a0 = s.expr();
                s.fin(&nm, vec![n("subcmd", hex8(sc)), ne("arg0", a0)])
            } else if matches!(sc, 0x12 | 0x13 | 0x14) {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin(&nm, vec![n("subcmd", hex8(sc)), ne("arg0", a0), ne("arg1", a1)])
            } else if sc == 0x15 {
                let a0 = s.expr();
                let a1 = s.expr();
                let a2 = s.expr();
                s.fin(&nm, vec![n("subcmd", hex8(sc)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
            } else {
                s.subcmd(&nm, sc)
            }
        }
        0x30 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0030")) };
            s.mode("op_0030", m)
        }
        0x31 => {
            let Some(m) = s.byte() else { return Some(s.trunc(&s.opcode_name.to_ascii_lowercase())) };
            let nm = s.opcode_name.to_ascii_lowercase();
            let a0 = s.expr();
            s.fin(&nm, vec![n("mode", hex8(m)), ne("arg0", a0)])
        }
        0x32 => s.fin0("op_0032"),
        0x33 => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_0033", vec![pe(a0), pe(a1)])
        }
        0x34 => s.fin0("op_0034"),
        0x35 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0035")) };
            s.mode("op_0035", m)
        }
        0x36 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0036")) };
            s.mode("op_0036", m)
        }
        0x37 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0037")) };
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_0037", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
        }
        0x38 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0038")) };
            let a0 = s.expr();
            s.fin("op_0038", vec![n("mode", hex8(m)), pe(a0)])
        }
        0x39 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0039")) };
            s.mode("op_0039", m)
        }
        0x3A => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_003a")) };
            if m == 0 {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin("op_003a", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
            } else if matches!(m, 2 | 3) {
                let a0 = s.expr();
                s.fin("op_003a", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.mode("op_003a", m)
            }
        }
        0x3B => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_003b")) };
            s.mode("op_003b", m)
        }
        0x3C => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_003c")) };
            s.mode("op_003c", m)
        }
        0x3D => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_003d", vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x3E => s.fin0("op_003e"),
        0x3F => s.fin0("op_003f"),
        0x40 => s.fin0("op_0040"),
        0x41 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0041")) };
            s.mode("op_0041", m)
        }
        0x42 => {
            let e = s.expr();
            s.fin("op_0042", vec![ne("arg0", e)])
        }
        0x43 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("text_window_ctrl")) };
            let op = mode & 0x0F;
            if op == 2 {
                let e = s.expr();
                s.fin("text_window_ctrl", vec![n("mode", hex8(mode)), n("op", op.to_string()), pe(e)])
            } else if matches!(op, 3 | 4) {
                let Some(flag) = s.byte() else {
                    return Some(s.fin("text_window_ctrl", vec![n("mode", hex8(mode)), n("op", op.to_string()), n("trunc", "1")]));
                };
                let mut ops = vec![n("mode", hex8(mode)), n("op", op.to_string()), n("flag", hex8(flag))];
                if flag == 1 {
                    let e = s.expr();
                    ops.push(pe(e));
                }
                if (mode & 0x80) != 0 {
                    if (mode & 0x40) != 0 {
                        let e = s.expr();
                        ops.push(ne("bsh_script", e));
                    }
                    let e = s.expr();
                    ops.push(ne("bsh_key", e));
                    return Some(s.fin("text_window_ctrl", ops));
                }
                let Some(ti) = s.u16_val() else {
                    ops.push(n("trunc", "1"));
                    return Some(s.fin("text_window_ctrl", ops));
                };
                ops.push(n("text", format!("table1[{}]", fmt_u16(ti))));
                s.fin("text_window_ctrl", ops)
            } else {
                s.fin("text_window_ctrl", vec![n("mode", hex8(mode)), n("op", op.to_string())])
            }
        }
        0x44 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0044")) };
            s.mode("op_0044", m)
        }
        0x45 => s.fin0("op_0045"),
        0x46 => {
            let a0 = s.expr();
            s.fin("op_0046", vec![ne("arg0", a0)])
        }
        0x47 => s.fin0("op_0047"),
        0x48 => s.fin0("op_0048"),
        0x49 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0049")) };
            s.mode("op_0049", m)
        }
        0x4A => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_004a")) };
            s.mode("op_004a", m)
        }
        0x4B => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_004b")) };
            s.mode("op_004b", m)
        }
        0x4C => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_004c")) };
            if m == 0 {
                let a0 = s.expr();
                s.fin("op_004c", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.mode("op_004c", m)
            }
        }
        0x4D => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_004d")) };
            let a0 = s.expr();
            s.fin("op_004d", vec![n("mode", hex8(m)), ne("arg0", a0)])
        }
        0x4E => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_004e")) };
            let entry = s.expr();
            if m == 0 {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin("op_004e", vec![n("mode", hex8(m)), ne("entry", entry), ne("arg0", a0), ne("arg1", a1)])
            } else if m == 1 {
                let a0 = s.expr();
                let a1 = s.expr();
                let a2 = s.expr();
                s.fin("op_004e", vec![n("mode", hex8(m)), ne("entry", entry), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
            } else {
                s.fin("op_004e", vec![n("mode", hex8(m)), ne("entry", entry)])
            }
        }
        0x4F => {
            let e = s.expr();
            s.fin("op_004f", vec![ne("arg0", e)])
        }
        0x50 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0050")) };
            let a0 = s.expr();
            s.fin("op_0050", vec![n("mode", hex8(m)), ne("arg0", a0)])
        }
        0x51 => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x52 => s.fin0("op_0052"),
        0x53 => {
            let Some(flags) = s.byte() else { return Some(s.trunc("op_0053")) };
            let a0 = s.expr();
            let Some(t) = s.u16_val() else {
                return Some(s.fin("op_0053", vec![n("flags", hex8(flags)), ne("arg0", a0), n("trunc", "1")]));
            };
            s.fin("op_0053", vec![n("flags", hex8(flags)), ne("arg0", a0), n("target", fmt_l0(t))])
        }
        0x54 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0054")) };
            let a0 = s.expr();
            let Some(t0) = s.u16_val() else { return Some(s.fin("op_0054", vec![n("mode", hex8(m)), ne("arg0", a0), n("trunc", "1")])) };
            let Some(t1) = s.u16_val() else { return Some(s.fin("op_0054", vec![n("mode", hex8(m)), ne("arg0", a0), n("trunc", "1")])) };
            s.fin("op_0054", vec![n("mode", hex8(m)), ne("arg0", a0), n("target0", fmt_l0(t0)), n("target1", fmt_l0(t1))])
        }
        0x55 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0055")) };
            let a0 = s.expr();
            let script = s.expr();
            let Some(t) = s.u16_val() else {
                return Some(s.fin("op_0055", vec![n("mode", hex8(m)), ne("arg0", a0), ne("script", script), n("trunc", "1")]));
            };
            s.fin("op_0055", vec![n("mode", hex8(m)), ne("arg0", a0), ne("script", script), n("target", fmt_u16(t))])
        }
        0x56 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0056")) };
            let a0 = s.expr();
            let a1 = s.expr();
            let Some(a2) = s.u16_val() else {
                return Some(s.fin("op_0056", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), n("trunc", "1")]));
            };
            let Some(a3) = s.u16_val() else {
                return Some(s.fin("op_0056", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), n("trunc", "1")]));
            };
            s.fin("op_0056", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), n("arg2", fmt_u16(a2)), n("arg3", fmt_u16(a3))])
        }
        0x57 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0057")) };
            let a0 = s.expr();
            s.fin("op_0057", vec![n("mode", hex8(m)), ne("arg0", a0)])
        }
        0x58 => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x59 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0059")) };
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_0059", vec![n("mode", hex8(m)), pe(a0), pe(a1)])
        }
        0x5A => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_005a")) };
            let a0 = s.expr();
            if m == 0 {
                let Some(a1) = s.u16_val() else { return Some(s.fin("op_005a", vec![n("mode", hex8(m)), ne("arg0", a0), n("trunc", "1")])) };
                s.fin("op_005a", vec![n("mode", hex8(m)), ne("arg0", a0), n("arg1", fmt_u16(a1))])
            } else {
                s.fin("op_005a", vec![n("mode", hex8(m)), ne("arg0", a0)])
            }
        }
        0x5B => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x5C => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_005c")) };
            if m == 1 {
                let name = s.cstring();
                s.fin("op_005c", vec![n("mode", hex8(m)), n("text", format!("\"{name}\""))])
            } else {
                s.mode("op_005c", m)
            }
        }
        0x5D => {
            let a0 = s.expr();
            s.fin("op_005d", vec![ne("arg0", a0)])
        }
        0x5E => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_005e")) };
            s.mode("op_005e", m)
        }
        0x5F => {
            let Some(sc) = s.byte() else { return Some(s.trunc("op_005f")) };
            if matches!(sc, 1 | 2) {
                let a0 = s.expr();
                s.fin("op_005f", vec![n("subcmd", hex8(sc)), ne("arg0", a0)])
            } else {
                s.subcmd("op_005f", sc)
            }
        }
        0x60 => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        _ => return None,
    })
}

// ── Table 01 ──

fn table01(s: &mut St) -> Option<IlInstruction> {
    Some(match s.opcode_id {
        0x00 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0100")) };
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            s.fin("op_0100", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
        }
        0x01 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0101")) };
            if m == 1 {
                let a0 = s.expr();
                s.fin("op_0101", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.fin("op_0101", vec![n("mode", hex8(m))])
            }
        }
        0x02 => {
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            s.fin("op_0102", vec![ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
        }
        0x03 => s.stub(),
        0x04 => {
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            let a3 = s.expr();
            let a4 = s.expr();
            s.fin("op_0104", vec![ne("arg0", a0), ne("arg1", a1), ne("arg2", a2), ne("arg3", a3), ne("arg4", a4)])
        }
        0x05 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0105")) };
            if matches!(m, 0 | 1) {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin("op_0105", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
            } else if m == 2 {
                let a0 = s.expr();
                let a1 = s.expr();
                let a2 = s.expr();
                s.fin("op_0105", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
            } else {
                return None;
            }
        }
        0x06 => {
            let Some(sc) = s.byte() else { return Some(s.trunc("op_0106")) };
            if sc == 0 {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin("op_0106", vec![n("subcmd", hex8(sc)), ne("arg0", a0), ne("arg1", a1)])
            } else if sc == 1 {
                let a0 = s.expr();
                let a1 = s.expr();
                let a2 = s.expr();
                s.fin("op_0106", vec![n("subcmd", hex8(sc)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
            } else {
                return None;
            }
        }
        0x07 => {
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            s.fin("op_0107", vec![ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
        }
        0x08 => {
            let Some(sc) = s.byte() else { return Some(s.trunc("op_0108")) };
            if sc == 0x0A {
                let a0 = s.expr();
                s.fin("op_0108", vec![n("subcmd", hex8(sc)), ne("arg0", a0)])
            } else {
                s.subcmd("op_0108", sc)
            }
        }
        0x09 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("select_dialogue_slot")) };
            let kind = mode & 0x7F;
            if kind == 0 {
                let Some(vid) = s.u16_val() else { return Some(s.trunc("select_dialogue_slot")) };
                s.fin("select_dialogue_slot", vec![n("mode", hex8(mode)), n("voice_id", fmt_u16(vid))])
            } else if kind == 1 {
                let mut ops = vec![n("mode", hex8(mode))];
                if (mode & 0x80) != 0 {
                    let Some(vid) = s.u16_val() else { return Some(s.trunc("select_dialogue_slot")) };
                    ops.push(n("voice_id", fmt_u16(vid)));
                }
                let e = s.expr();
                ops.push(ne("slot", e));
                s.fin("select_dialogue_slot", ops)
            } else if kind == 2 {
                let e = s.expr();
                s.fin("select_dialogue_slot", vec![n("mode", hex8(mode)), ne("slot", e)])
            } else {
                return None;
            }
        }
        0x0A => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_010a")) };
            if m != 4 && m != 5 && (m & 1) == 0 {
                let a0 = s.expr();
                s.fin("op_010a", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.fin("op_010a", vec![n("mode", hex8(m))])
            }
        }
        0x0B => s.fin0("prepare_dialogue_line"),
        0x0C => {
            let Some(flags) = s.byte() else { return Some(s.trunc("slot_text_show")) };
            let mut ops = vec![n("flags", hex8(flags))];
            if (flags & 1) != 0 {
                let e = s.expr();
                ops.push(ne("arg0", e));
            }
            let e1 = s.expr();
            ops.push(ne("arg1", e1));
            if (flags & 2) != 0 {
                let e = s.expr();
                ops.push(ne("arg2", e));
            }
            if (flags & 0x80) != 0 {
                let e = s.expr();
                ops.push(ne("text_key", e));
                return Some(s.fin("slot_text_show", ops));
            }
            let Some(ti) = s.u16_val() else {
                ops.push(n("trunc", "1"));
                return Some(s.fin("slot_text_show", ops));
            };
            ops.push(n("text_ref", format!("table1[{}]", fmt_u16(ti))));
            s.fin("slot_text_show", ops)
        }
        0x0D => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_010d")) };
            s.mode("op_010d", m)
        }
        0x0E => {
            let a0 = s.expr();
            let Some(lbl) = s.u16_val() else { return Some(s.fin("op_010e", vec![ne("arg0", a0), n("trunc", "1")])) };
            s.fin("op_010e", vec![ne("arg0", a0), n("label", fmt_u16(lbl))])
        }
        0x0F => {
            let Some(a0) = s.u16_val() else { return Some(s.trunc("op_010f")) };
            let Some(a1) = s.u16_val() else { return Some(s.trunc("op_010f")) };
            s.fin("op_010f", vec![n("arg0", fmt_u16(a0)), n("arg1", fmt_u16(a1))])
        }
        0x10 => {
            let Some(b) = s.byte() else { return Some(s.trunc("op_0110")) };
            s.subcmd("op_0110", b)
        }
        0x11 => {
            let Some(sc) = s.byte() else { return Some(s.trunc("slot_ui_effect")) };
            if matches!(sc, 5 | 6 | 7 | 8) {
                let e = s.expr();
                s.fin("slot_ui_effect", vec![n("subcmd", hex8(sc)), ne("slot", e)])
            } else {
                s.subcmd("slot_ui_effect", sc)
            }
        }
        0x12 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("main_text_control")) };
            if mode == 0 {
                let Some(mid) = s.u16_val() else { return Some(s.fin("main_text_control", vec![n("mode", hex8(mode)), n("trunc", "1")])) };
                let tail = s.expr();
                s.fin("main_text_control", vec![n("mode", hex8(mode)), n("clear_id", fmt_u16(mid)), ne("tail", tail), n("clear_queue", "1")])
            } else {
                let eff = if (mode & 0x80) != 0 { mode - 0x80 } else { mode };
                let mut ops = vec![n("mode", hex8(mode))];
                if (mode & 0x80) != 0 {
                    let key = s.expr();
                    ops.push(n("text_id", format!("peek_expr_text_id({})", crate::expr::render_expr(&key))));
                    ops.push(n("text_id_src", "expr_lookup"));
                    ops.push(ne("text_key", key));
                } else {
                    let Some(mid) = s.u16_val() else {
                        ops.push(n("trunc", "1"));
                        return Some(s.fin("main_text_control", ops));
                    };
                    ops.push(n("text_id", fmt_u16(mid)));
                    let Some(ti) = s.u16_val() else {
                        ops.push(n("trunc", "1"));
                        return Some(s.fin("main_text_control", ops));
                    };
                    ops.push(n("text_ref", format!("table1[{}]", fmt_u16(ti))));
                }
                if eff == 2 {
                    let cnt = s.expr();
                    ops.push(ne("count", cnt));
                }
                s.fin("main_text_control", ops)
            }
        }
        0x13 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("op_0113")) };
            if mode == 0 {
                let raw = s.raw_bytes(12);
                s.fin("op_0113", vec![n("mode", hex8(mode)), n("opaque12", raw)])
            } else if mode == 2 {
                let a0 = s.expr();
                s.fin("op_0113", vec![n("mode", hex8(mode)), ne("arg0", a0)])
            } else {
                s.fin("op_0113", vec![n("mode", hex8(mode))])
            }
        }
        0x14 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("text_sub")) };
            if matches!(mode, 0 | 1) {
                s.fin("text_sub", vec![n("mode", hex8(mode))])
            } else if (mode & 0x80) != 0 {
                let key = s.expr();
                s.fin("text_sub", vec![n("mode", hex8(mode)), ne("text_key", key), n("sub", (mode as i32 - 0x82).to_string())])
            } else {
                let Some(ti) = s.u16_val() else { return Some(s.fin("text_sub", vec![n("mode", hex8(mode)), n("trunc", "1")])) };
                s.fin("text_sub", vec![n("mode", hex8(mode)), n("text", format!("table1[{}]", fmt_u16(ti))), n("sub", (mode as i32 - 2).to_string())])
            }
        }
        0x15 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("op_0115")) };
            let slot = mode >> 4;
            let sc = mode & 0x0F;
            if sc == 0 {
                let e0 = s.expr();
                let e1 = s.expr();
                s.fin("op_0115", vec![n("slot", hex8(slot)), n("subcmd", hex8(sc)), ne("threshold", e0), ne("fallback_value", e1)])
            } else if matches!(sc, 2 | 3) {
                let e0 = s.expr();
                s.fin("op_0115", vec![n("slot", hex8(slot)), n("subcmd", hex8(sc)), ne("dst_var", e0)])
            } else {
                s.fin("op_0115", vec![n("slot", hex8(slot)), n("subcmd", hex8(sc))])
            }
        }
        0x16 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0116")) };
            if m != 0 {
                let a0 = s.expr();
                s.fin("op_0116", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.fin("op_0116", vec![n("mode", hex8(m))])
            }
        }
        0x17..=0x1D => s.stub(),
        0x1E => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_011e")) };
            if matches!(m, 0 | 4 | 5) {
                let a0 = s.expr();
                s.fin("op_011e", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else if matches!(m, 1 | 9 | 0x14 | 0x15) {
                let args: Vec<ExprValue> = (0..4).map(|_| s.expr()).collect();
                let Some(tail) = s.byte() else {
                    return Some(s.fin(
                        "op_011e",
                        vec![
                            n("mode", hex8(m)),
                            ne("arg0", args[0].clone()),
                            ne("arg1", args[1].clone()),
                            ne("arg2", args[2].clone()),
                            ne("arg3", args[3].clone()),
                            n("trunc", "1"),
                        ],
                    ));
                };
                s.fin(
                    "op_011e",
                    vec![
                        n("mode", hex8(m)),
                        ne("arg0", args[0].clone()),
                        ne("arg1", args[1].clone()),
                        ne("arg2", args[2].clone()),
                        ne("arg3", args[3].clone()),
                        n("tail", hex8(tail)),
                    ],
                )
            } else if m == 6 {
                let args: Vec<ExprValue> = (0..5).map(|_| s.expr()).collect();
                s.fin(
                    "op_011e",
                    vec![
                        n("mode", hex8(m)),
                        ne("arg0", args[0].clone()),
                        ne("arg1", args[1].clone()),
                        ne("arg2", args[2].clone()),
                        ne("arg3", args[3].clone()),
                        ne("arg4", args[4].clone()),
                    ],
                )
            } else {
                s.fin("op_011e", vec![n("mode", hex8(m))])
            }
        }
        0x1F => s.stub(),
        0x20 => {
            let a0 = s.expr();
            s.fin("op_0120", vec![ne("arg0", a0)])
        }
        0x21 => {
            let a0 = s.expr();
            let Some(lbl) = s.u16_val() else { return Some(s.fin("op_0121", vec![ne("arg0", a0), n("trunc", "1")])) };
            s.fin("op_0121", vec![ne("arg0", a0), n("label", fmt_u16(lbl))])
        }
        0x22 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0122")) };
            let mut ops = vec![n("mode", hex8(m))];
            if m == 0x63 {
                let e0 = s.expr();
                let e1 = s.expr();
                ops.push(ne("arg0", e0));
                ops.push(ne("arg1", e1));
            } else {
                let Some(a1) = s.byte() else {
                    ops.push(n("trunc", "1"));
                    return Some(s.fin("op_0122", ops));
                };
                ops.push(n("arg1", hex8(a1)));
            }
            let e2 = s.expr();
            let e3 = s.expr();
            ops.push(ne("arg2", e2));
            ops.push(ne("arg3", e3));
            s.fin("op_0122", ops)
        }
        0x23 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0123")) };
            s.mode("op_0123", m)
        }
        0x24 => s.stub(),
        0x25 => {
            let Some(mode) = s.byte() else { return Some(s.trunc("text_variant")) };
            let sub = mode & 0x0F;
            let dyn_ = (mode & 0x80) != 0;
            let mut ops = vec![n("mode", hex8(mode)), n("sub", sub.to_string())];
            if sub == 1 {
                let e0 = s.expr();
                let e1 = s.expr();
                ops.push(ne("expr_a", e0));
                ops.push(ne("expr_b", e1));
            }
            if dyn_ {
                let key = s.expr();
                ops.push(n("id", format!("peek_expr_text_id({})", crate::expr::render_expr(&key))));
                ops.push(n("id_src", "expr_lookup"));
                ops.push(ne("text_key", key));
            } else {
                let Some(mid) = s.u16_val() else {
                    ops.push(n("trunc", "1"));
                    return Some(s.fin("text_variant", ops));
                };
                ops.push(n("id", fmt_u16(mid)));
                let Some(ti) = s.u16_val() else {
                    ops.push(n("trunc", "1"));
                    return Some(s.fin("text_variant", ops));
                };
                ops.push(n("text", format!("table1[{}]", fmt_u16(ti))));
            }
            if sub == 3 {
                let e0 = s.expr();
                let e1 = s.expr();
                let e2 = s.expr();
                ops.push(pe(e0));
                ops.push(pe(e1));
                ops.push(pe(e2));
            }
            s.fin("text_variant", ops)
        }
        0x26 => s.stub(),
        0x27 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0127")) };
            s.mode("op_0127", m)
        }
        0x28 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0128")) };
            if matches!(m, 2 | 3) {
                let Some(raw) = s.u16_val() else { return Some(s.fin("op_0128", vec![n("mode", hex8(m)), n("trunc", "1")])) };
                s.fin("op_0128", vec![n("mode", hex8(m)), n("raw_u16", fmt_u16(raw))])
            } else if matches!(m, 4 | 5 | 6) {
                let a0 = s.expr();
                s.fin("op_0128", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.fin("op_0128", vec![n("mode", hex8(m))])
            }
        }
        0x29..=0x2B => s.stub(),
        0x2C => {
            let Some(mode) = s.byte() else { return Some(s.trunc("op_012c")) };
            let low = mode & 0x1F;
            let group = low / 4;
            let sc = low % 4;
            let mut ops = vec![n("mode", hex8(mode)), n("group", group.to_string()), n("subcmd", sc.to_string())];
            if sc == 0 {
                let Some(ti) = s.u16_val() else {
                    ops.push(n("trunc", "1"));
                    return Some(s.fin("op_012c", ops));
                };
                let Some(cmd) = s.byte() else {
                    ops.push(n("trunc", "1"));
                    return Some(s.fin("op_012c", ops));
                };
                ops.push(n("table1", fmt_u16(ti)));
                ops.push(n("cmd", hex8(cmd)));
            } else if sc == 2 {
                let e = s.expr();
                ops.push(ne("arg0", e));
            } else if sc == 3 {
                let e0 = s.expr();
                let e1 = s.expr();
                ops.push(ne("arg0", e0));
                ops.push(ne("arg1", e1));
            }
            s.fin("op_012c", ops)
        }
        0x2D => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_012d")) };
            if m == 2 {
                let a0 = s.expr();
                s.fin("op_012d", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.fin("op_012d", vec![n("mode", hex8(m))])
            }
        }
        0x2E | 0x2F => s.stub(),
        0x30 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_0130")) };
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            let mut ops = vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)];
            if m != 0 {
                for i in 3..=8 {
                    let e = s.expr();
                    ops.push(ne(&format!("arg{i}"), e));
                }
            }
            s.fin("op_0130", ops)
        }
        0x31 => {
            let Some(sc) = s.byte() else { return Some(s.trunc("op_0131")) };
            if s.p >= s.max {
                return Some(s.fin("op_0131", vec![n("subcmd", hex8(sc)), n("trunc", "1")]));
            }
            match sc {
                0 => {
                    let a0 = s.byte().unwrap();
                    s.fin("op_0131", vec![n("subcmd", hex8(sc)), n("arg0", hex8(a0))])
                }
                1 => {
                    let a0 = s.byte().unwrap();
                    let a1 = s.expr();
                    let a2 = s.expr();
                    let a3 = s.expr();
                    s.fin("op_0131", vec![n("subcmd", hex8(sc)), n("arg0", hex8(a0)), ne("arg1", a1), ne("arg2", a2), ne("arg3", a3)])
                }
                2 => {
                    let a0 = s.byte().unwrap();
                    s.fin("op_0131", vec![n("subcmd", hex8(sc)), n("arg0", hex8(a0))])
                }
                3 => {
                    let a0 = s.byte().unwrap();
                    let a1 = s.expr();
                    let a2 = s.expr();
                    s.fin("op_0131", vec![n("subcmd", hex8(sc)), n("arg0", hex8(a0)), ne("arg1", a1), ne("arg2", a2)])
                }
                _ => s.subcmd("op_0131", sc),
            }
        }
        0x32..=0x40 => s.stub(),
        _ => return None,
    })
}

// ── Table 10 ──

fn table10(s: &mut St) -> Option<IlInstruction> {
    Some(match s.opcode_id {
        0x00 => {
            let e = s.expr();
            s.fin("op_0066_01c6_1000", vec![ne("action", e)])
        }
        0x01 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
            let a0 = s.expr();
            let a1 = s.expr();
            if (m & 0x7F) == 0x10 {
                let a2 = s.expr();
                s.fin(&nm, vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
            } else {
                s.fin(&nm, vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
            }
        }
        0x02 => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_1002", vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x03 => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_1003", vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x04 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1004")) };
            let a0 = s.expr();
            let a1 = s.expr();
            if m >= 4 {
                let a2 = s.expr();
                let a3 = s.expr();
                s.fin("op_1004", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2), ne("arg3", a3)])
            } else {
                let a3 = s.expr();
                s.fin("op_1004", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), ne("arg3", a3)])
            }
        }
        0x05 => {
            let e = s.expr();
            s.fin("op_1005", vec![ne("arg0", e)])
        }
        0x06 => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_1006", vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x07 => {
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_1007", vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x08 => s.stub(),
        0x09 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin(&nm, vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x0A => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x0B => s.fin0("op_100b"),
        0x0C => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
            s.mode(&nm, m)
        }
        0x0D => s.stub(),
        0x0E => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin(&nm, vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x0F => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_100f")) };
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_100f", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
        }
        0x10 => {
            let e = s.expr();
            s.fin("op_1010", vec![ne("arg0", e)])
        }
        0x11 => s.stub(),
        0x12 => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x13 => {
            let Some(sc) = s.byte() else { return Some(s.trunc("op_1013")) };
            if sc == 5 {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin("op_1013", vec![n("subcmd", hex8(sc)), ne("arg0", a0), ne("arg1", a1)])
            } else {
                s.subcmd("op_1013", sc)
            }
        }
        0x14 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1014")) };
            s.mode("op_1014", m)
        }
        0x15 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
            s.mode(&nm, m)
        }
        0x16 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin(&nm, vec![ne("arg0", a0), ne("arg1", a1)])
        }
        0x17 => {
            let a0 = s.expr();
            s.fin("op_1017", vec![ne("arg0", a0)])
        }
        0x18 | 0x19 => s.stub(),
        0x1A => {
            let Some(b) = s.byte() else { return Some(s.trunc("op_101a")) };
            s.subcmd("op_101a", b)
        }
        0x1B => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
            s.mode(&nm, m)
        }
        0x1C => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
            s.mode(&nm, m)
        }
        0x1D => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_101d")) };
            s.mode("op_101d", m)
        }
        0x1E => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x1F => {
            let Some(b) = s.byte() else { return Some(s.trunc("op_101f")) };
            s.subcmd("op_101f", b)
        }
        0x20 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
            s.mode(&nm, m)
        }
        0x21 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1021")) };
            s.mode("op_1021", m)
        }
        0x22 => {
            let Some(m) = s.byte() else { return Some(s.trunc("snapshot_control")) };
            if m == 0x0A {
                let Some(vid) = s.u16_val() else { return Some(s.trunc("snapshot_control")) };
                s.fin("snapshot_control", vec![n("mode", hex8(m)), n("aux_id", fmt_u16(vid))])
            } else {
                s.fin("snapshot_control", vec![n("mode", hex8(m))])
            }
        }
        0x23 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(sc) = s.byte() else { return Some(s.trunc(&nm)) };
            if sc == 0 {
                let Some(a0) = s.byte() else { return Some(s.fin(&nm, vec![n("subcmd", hex8(sc)), n("trunc", "1")])) };
                s.fin(&nm, vec![n("subcmd", hex8(sc)), n("arg0", hex8(a0))])
            } else {
                s.subcmd(&nm, sc)
            }
        }
        0x24 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1024")) };
            if m == 0 {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin("op_1024", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
            } else {
                s.fin("op_1024", vec![n("mode", hex8(m))])
            }
        }
        0x25 | 0x26 => s.stub(),
        0x27 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1027")) };
            let a0 = s.expr();
            if m == 1 {
                let a1 = s.expr();
                s.fin("op_1027", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
            } else {
                s.fin("op_1027", vec![n("mode", hex8(m)), ne("arg0", a0)])
            }
        }
        0x28 => {
            let a0 = s.expr();
            s.fin("op_1028", vec![ne("arg0", a0)])
        }
        0x29 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1029")) };
            let a0 = s.expr();
            s.fin("op_1029", vec![n("mode", hex8(m)), ne("arg0", a0)])
        }
        0x2A => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_102a")) };
            let a0 = s.expr();
            let a1 = s.expr();
            let a2 = s.expr();
            s.fin("op_102a", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1), ne("arg2", a2)])
        }
        0x2B => s.stub(),
        0x2C => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(sc) = s.byte() else { return Some(s.trunc(&nm)) };
            match sc {
                0 => {
                    let entry = s.expr();
                    let p0 = s.expr();
                    let p1 = s.expr();
                    s.fin(&nm, vec![n("subcmd", hex8(sc)), ne("entry", entry), ne("param0", p0), ne("param1", p1)])
                }
                1 => {
                    let entry = s.expr();
                    let p0 = s.expr();
                    let p1 = s.expr();
                    let p2 = s.expr();
                    let p3 = s.expr();
                    s.fin(&nm, vec![n("subcmd", hex8(sc)), ne("entry", entry), ne("param0", p0), ne("param1", p1), ne("param2", p2), ne("param3", p3)])
                }
                2 => {
                    let entry = s.expr();
                    s.fin(&nm, vec![n("subcmd", hex8(sc)), ne("entry", entry)])
                }
                3 => {
                    let entry = s.expr();
                    let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
                    s.fin(&nm, vec![n("subcmd", hex8(sc)), ne("entry", entry), n("mode", hex8(m))])
                }
                4 => {
                    let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
                    if m != 0 {
                        s.fin(&nm, vec![n("subcmd", hex8(sc)), n("mode", hex8(m))])
                    } else {
                        let entry = s.expr();
                        s.fin(&nm, vec![n("subcmd", hex8(sc)), n("mode", hex8(m)), ne("entry", entry)])
                    }
                }
                0x0A => s.subcmd(&nm, sc),
                _ => return None,
            }
        }
        0x2D => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x2E => {
            let a0 = s.expr();
            s.fin("op_102e", vec![ne("arg0", a0)])
        }
        0x2F => s.fin0(&s.opcode_name.to_ascii_lowercase()),
        0x30 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1030")) };
            if matches!(m, 1 | 3 | 0x0B) {
                let args: Vec<ExprValue> = (0..5).map(|_| s.expr()).collect();
                s.fin(
                    "op_1030",
                    vec![
                        n("mode", hex8(m)),
                        ne("arg0", args[0].clone()),
                        ne("arg1", args[1].clone()),
                        ne("arg2", args[2].clone()),
                        ne("arg3", args[3].clone()),
                        ne("arg4", args[4].clone()),
                    ],
                )
            } else if matches!(m, 4 | 5 | 0x0C) {
                let args: Vec<ExprValue> = (0..6).map(|_| s.expr()).collect();
                s.fin(
                    "op_1030",
                    vec![
                        n("mode", hex8(m)),
                        ne("arg0", args[0].clone()),
                        ne("arg1", args[1].clone()),
                        ne("arg2", args[2].clone()),
                        ne("arg3", args[3].clone()),
                        ne("arg4", args[4].clone()),
                        ne("arg5", args[5].clone()),
                    ],
                )
            } else {
                s.fin("op_1030", vec![n("mode", hex8(m))])
            }
        }
        0x31 | 0x32 => s.stub(),
        0x33 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1033")) };
            if m == 0 {
                let Some(t0) = s.u16_val() else { return Some(s.trunc("op_1033")) };
                let Some(t1) = s.u16_val() else { return Some(s.trunc("op_1033")) };
                let Some(raw) = s.u16_val() else { return Some(s.trunc("op_1033")) };
                s.fin("op_1033", vec![n("mode", hex8(m)), n("target0", fmt_l0(t0)), n("target1", fmt_l0(t1)), n("raw_u16", fmt_u16(raw))])
            } else {
                s.fin("op_1033", vec![n("mode", hex8(m))])
            }
        }
        0x34 => {
            let Some(b) = s.byte() else { return Some(s.trunc("op_1034")) };
            s.subcmd("op_1034", b)
        }
        0x35 => s.stub(),
        0x36 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(m) = s.byte() else { return Some(s.trunc(&nm)) };
            s.mode(&nm, m)
        }
        0x37 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_1037")) };
            if matches!(m, 0 | 2 | 3) {
                let a0 = s.expr();
                s.fin("op_1037", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.fin("op_1037", vec![n("mode", hex8(m))])
            }
        }
        0x38 | 0x39 => s.stub(),
        0x3A => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_103a")) };
            if matches!(m, 0 | 2) {
                let a0 = s.expr();
                let a1 = s.expr();
                s.fin("op_103a", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
            } else {
                s.fin("op_103a", vec![n("mode", hex8(m))])
            }
        }
        0x3B => s.stub(),
        0x3C => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_103c")) };
            let a0 = s.expr();
            let a1 = s.expr();
            s.fin("op_103c", vec![n("mode", hex8(m)), ne("arg0", a0), ne("arg1", a1)])
        }
        0x3D => {
            let a0 = s.expr();
            s.fin("op_103d", vec![ne("arg0", a0)])
        }
        0x3E..=0x40 => s.stub(),
        _ => return None,
    })
}

// ── Table 20 ──

fn table20(s: &mut St) -> Option<IlInstruction> {
    Some(match s.opcode_id {
        0x00..=0x0F => s.stub(),
        0x10 => {
            let Some(m) = s.byte() else { return Some(s.trunc("op_2010")) };
            if matches!(m, 0 | 0x20) {
                let a0 = s.expr();
                s.fin("op_2010", vec![n("mode", hex8(m)), ne("arg0", a0)])
            } else {
                s.fin("op_2010", vec![n("mode", hex8(m))])
            }
        }
        0x11 | 0x12 => {
            let nm = s.opcode_name.to_ascii_lowercase();
            let Some(b) = s.byte() else { return Some(s.trunc(&nm)) };
            s.subcmd(&nm, b)
        }
        0x13..=0x40 => s.stub(),
        _ => return None,
    })
}
