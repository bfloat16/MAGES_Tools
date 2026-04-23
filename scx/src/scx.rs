use anyhow::{Result, bail};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::expr::*;
use crate::format::*;
use crate::il::*;
use crate::opcode::*;

// ── constants ──

pub const SCX_TABLE0_START: usize = 0x0C;
pub const SCX_TABLE0_COUNT: usize = 0x1000;
pub const SCX_TABLE0_END: usize = SCX_TABLE0_START + SCX_TABLE0_COUNT * 4;

// ── ScxFile ──

pub struct ScxFile {
    pub path: String,
    pub data: Vec<u8>,
    pub off1: u32,
    pub off2: u32,
    pub table0: Vec<u32>,
    pub table1: Vec<u32>,
    pub table2: Vec<u32>,
}

impl ScxFile {
    pub fn code_start(&self) -> usize {
        SCX_TABLE0_END
    }
    pub fn code_end(&self) -> usize {
        self.off1 as usize
    }
}

// ── parsing ──

pub fn parse_scx(path: &Path) -> Result<ScxFile> {
    let data = std::fs::read(path)?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if data.len() < 12 || &data[..4] != b"SC3\0" {
        bail!("{name}: not a valid SC3 file");
    }

    let off1 = read_u32_le(&data, 4);
    let off2 = read_u32_le(&data, 8);
    let size = data.len() as u32;
    if off1 < SCX_TABLE0_END as u32 || off1 > size || off2 > size || off2 < off1 {
        bail!("{name}: invalid offsets off1=0x{off1:X} off2=0x{off2:X} size=0x{size:X}");
    }

    let table0 = read_u32_array(&data, SCX_TABLE0_START, SCX_TABLE0_END);
    let table1 = read_u32_array(&data, off1 as usize, off2 as usize);
    let table2 = read_u32_array(&data, off2 as usize, data.len() & !3);

    Ok(ScxFile {
        path: path.to_string_lossy().into_owned(),
        data,
        off1,
        off2,
        table0,
        table1,
        table2,
    })
}

fn read_u32_array(data: &[u8], start: usize, end: usize) -> Vec<u32> {
    let end_aligned = end & !3;
    let count = end_aligned.saturating_sub(start) / 4;
    (0..count).map(|i| read_u32_le(data, start + i * 4)).collect()
}

// ── instruction checks ──

fn has_invalid_expressions(inst: &IlInstruction) -> bool {
    inst.operands.iter().any(|op| if let IlValue::Expr(ref e) = op.value { e.has_unknown_tokens() || !e.has_value_source() } else { false })
}

// ── ExecuteScxLoop (the VM decode loop) ──

pub fn execute_scx_loop(scx: &ScxFile, offset: usize, code_limit: usize) -> IlInstruction {
    let data = &scx.data;
    if offset >= code_limit {
        return IlInstruction::new(offset, offset, "eof");
    }

    // 0xFE prefix → expression
    if data[offset] == 0xFE {
        let (expr, end) = read_expr_value(data, offset + 1, code_limit);
        if expr.has_unknown_tokens() || !expr.has_value_source() {
            if offset + 1 < code_limit {
                let mut inst = IlInstruction::new(offset, offset + 2, "data_u16");
                inst.operands.push(IlOperand::named("", fmt_u16(read_u16_le(data, offset))));
                return inst;
            }
            let mut inst = IlInstruction::new(offset, offset + 1, "trunc_op");
            inst.operands.push(IlOperand::named("", format!("0x{:02X}", data[offset])));
            return inst;
        }
        let mut inst = IlInstruction::new(offset, end, "expr");
        inst.operands.push(IlOperand::pos_expr(expr));
        inst.comments.push("raw=00FE".into());
        return inst;
    }

    if offset + 1 >= code_limit {
        let mut inst = IlInstruction::new(offset, offset + 1, "trunc_op");
        inst.operands.push(IlOperand::named("", format!("0x{:02X}", data[offset])));
        return inst;
    }

    let major = data[offset] & 0x7F;
    let index = data[offset + 1];
    let opcode_id = ((major as u16) << 8) | index as u16;
    if !matches!(major, 0x00 | 0x01 | 0x10 | 0x20) {
        let mut inst = IlInstruction::new(offset, offset + 2, "data_u16");
        inst.operands.push(IlOperand::named("", fmt_u16(opcode_id)));
        return inst;
    }

    let known = decode_scx_known(scx, offset, code_limit);
    if known.mnemonic == "unknown_operands" || has_invalid_expressions(&known) {
        let mut inst = IlInstruction::new(offset, offset + 2, "data_u16");
        inst.operands.push(IlOperand::named("", fmt_u16(opcode_id)));
        return inst;
    }

    let mut result = known;
    result.comments.push(format!("raw={opcode_id:04X}"));
    result
}

// ── disassembler (control flow graph builder) ──

pub fn build_scx_document(scx: &ScxFile) -> IlDocument {
    let entries = entry_candidates(scx);
    let sweep_start = entries.iter().copied().min().unwrap_or(scx.code_start());
    let decoded = decode_reachable(scx);

    IlDocument {
        kind: IlDocumentKind::Scx,
        source_path: scx.path.clone(),
        size: scx.data.len(),
        off_table1: scx.off1,
        off_table2: scx.off2,
        code_start: scx.code_start(),
        code_end: scx.code_end(),
        sweep_start,
        msb_source_set: None,
        msb_raw_tail: None,
        instructions: decoded,
    }
}

fn decode_reachable(scx: &ScxFile) -> BTreeMap<usize, IlInstruction> {
    let entries = entry_candidates(scx);
    let mut pending: Vec<usize> = entries.clone();
    let mut known_starts: HashSet<usize> = entries.into_iter().collect();
    let mut decoded = BTreeMap::new();

    decode_pending(scx, &mut pending, &mut known_starts, &mut decoded);
    loop {
        let changed = rewrite_switch_tables(scx, &mut decoded);
        pending.clear();
        queue_switch_case_targets(scx, &decoded, &mut pending, &mut known_starts);
        if pending.is_empty() && !changed {
            break;
        }
        if !pending.is_empty() {
            decode_pending(scx, &mut pending, &mut known_starts, &mut decoded);
        }
    }

    decoded
}

fn decode_pending(scx: &ScxFile, pending: &mut Vec<usize>, known_starts: &mut HashSet<usize>, decoded: &mut BTreeMap<usize, IlInstruction>) {
    while !pending.is_empty() {
        let start = *pending.iter().min().unwrap();
        pending.retain(|&x| x != start);
        if decoded.contains_key(&start) || start < scx.code_start() || start >= scx.code_end() {
            continue;
        }

        let mut pc = start;
        while pc < scx.code_end() {
            if pc != start && known_starts.contains(&pc) {
                break;
            }
            if decoded.contains_key(&pc) {
                break;
            }

            let inst = execute_scx_loop(scx, pc, scx.code_end());
            collect_targets(scx, &inst, pending, known_starts);
            let no_fallthrough = !has_fallthrough(&inst) || inst.end <= pc;
            let end = inst.end;
            decoded.insert(pc, inst);
            if no_fallthrough {
                break;
            }
            pc = end;
        }
    }
}

fn rewrite_switch_tables(scx: &ScxFile, decoded: &mut BTreeMap<usize, IlInstruction>) -> bool {
    let mut changed = false;
    let mut switch_base_labels = HashSet::new();

    for inst in decoded.values() {
        if inst.mnemonic != "switch_jmp" {
            continue;
        }
        if let Some(tb) = inst.get_operand_value("table_base") {
            if let Some(idx) = try_parse_table_label(tb, "table0") {
                switch_base_labels.insert(idx);
            }
        }
    }

    for label_index in switch_base_labels {
        if label_index >= scx.table0.len() {
            continue;
        }
        let mut offset = scx.table0[label_index] as usize;
        loop {
            let Some(inst) = decoded.get(&offset) else { break };
            if inst.mnemonic != "data_u16" || inst.operands.len() != 1 {
                break;
            }
            let Some(text) = inst.operands[0].try_get_text() else { break };
            let Some(case_label) = try_parse_u16_literal(text) else { break };

            let target_str = fmt_l0(case_label as u16);
            let inst = decoded.get_mut(&offset).unwrap();
            if inst.mnemonic != "switch_case" || inst.get_operand_value("target") != Some(&target_str) {
                inst.mnemonic = "switch_case".into();
                inst.operands.clear();
                inst.operands.push(IlOperand::named("target", target_str));
                changed = true;
            }
            offset += 2;
        }
    }

    changed
}

fn queue_switch_case_targets(scx: &ScxFile, decoded: &BTreeMap<usize, IlInstruction>, pending: &mut Vec<usize>, known: &mut HashSet<usize>) {
    for inst in decoded.values() {
        if inst.mnemonic != "switch_case" {
            continue;
        }
        if let Some(target) = inst.get_operand_value("target") {
            if let Some(idx) = try_parse_table_label(target, "table0") {
                queue_table0_label(scx, idx, pending, known);
            }
        }
    }
}

fn entry_candidates(scx: &ScxFile) -> Vec<usize> {
    let mut entries = Vec::new();
    for i in 0..=1 {
        if i < scx.table0.len() {
            let offset = scx.table0[i] as usize;
            if offset >= scx.code_start() && offset < scx.code_end() && !entries.contains(&offset) {
                entries.push(offset);
            }
        }
    }
    if !scx.table2.is_empty() {
        let offset = scx.table2[0] as usize;
        if offset >= scx.code_start() && offset < scx.code_end() && !entries.contains(&offset) {
            entries.push(offset);
        }
    }
    entries
}

fn collect_targets(scx: &ScxFile, inst: &IlInstruction, pending: &mut Vec<usize>, known: &mut HashSet<usize>) {
    let op = inst.mnemonic.as_str();
    if matches!(
        op,
        "jmp_table0" | "jmp_if_expr" | "call_table0" | "call_script" | "loop_jmp" | "cmp_flag_jmp" | "call_context" | "cond_jmp_adv" | "op_0053" | "jmp_if_tmp_eq"
    ) {
        if let Some(target) = inst.get_operand_value("target") {
            if let Some(idx) = try_parse_table_label(target, "table0") {
                queue_table0_label(scx, idx, pending, known);
            }
        }
    }

    if op == "switch_jmp" {
        if let Some(case_target) = inst.get_operand_value("case_target") {
            if let Some(idx) = try_parse_table_label(case_target, "table0") {
                queue_table0_label(scx, idx, pending, known);
            }
        }
    }

    if matches!(op, "call_table0" | "call_script") {
        if let Some(ret) = inst.get_operand_value("ret") {
            if let Some(idx) = try_parse_table_label(ret, "table2") {
                queue_table2_label(scx, idx, pending, known);
            }
        }
    }
}

fn queue_table0_label(scx: &ScxFile, label_index: usize, pending: &mut Vec<usize>, known: &mut HashSet<usize>) {
    if label_index >= scx.table0.len() {
        return;
    }
    let offset = scx.table0[label_index] as usize;
    if offset >= scx.code_start() && offset < scx.code_end() && known.insert(offset) {
        pending.push(offset);
    }
}

fn queue_table2_label(scx: &ScxFile, label_index: usize, pending: &mut Vec<usize>, known: &mut HashSet<usize>) {
    if label_index >= scx.table2.len() {
        return;
    }
    let offset = scx.table2[label_index] as usize;
    if offset >= scx.code_start() && offset < scx.code_end() && known.insert(offset) {
        pending.push(offset);
    }
}

fn has_fallthrough(inst: &IlInstruction) -> bool {
    !matches!(inst.mnemonic.as_str(), "ret" | "break_vm" | "set_ctx_flag_and_break" | "set_stop_flag" | "jmp_table0" | "call_table0" | "call_script")
}

fn try_parse_table_label(value: &str, table_name: &str) -> Option<usize> {
    let prefix = format!("{table_name}[");
    if !value.starts_with(&prefix) || !value.ends_with(']') {
        return None;
    }
    let raw = &value[prefix.len()..value.len() - 1];
    try_parse_u16_literal(raw)
}

fn try_parse_u16_literal(value: &str) -> Option<usize> {
    let hex = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X"))?;
    usize::from_str_radix(hex, 16).ok()
}
