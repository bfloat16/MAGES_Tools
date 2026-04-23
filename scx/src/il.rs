use crate::expr::*;

// ── IL value types ──

#[derive(Clone, Debug)]
pub enum IlValue {
    Text(String),
    Expr(ExprValue),
}

#[derive(Clone, Debug)]
pub struct IlOperand {
    pub name: Option<String>,
    pub value: IlValue,
}

impl IlOperand {
    pub fn named(name: &str, text: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            value: IlValue::Text(text.into()),
        }
    }

    pub fn named_expr(name: &str, expr: ExprValue) -> Self {
        Self {
            name: Some(name.into()),
            value: IlValue::Expr(expr),
        }
    }

    pub fn pos_expr(expr: ExprValue) -> Self {
        Self { name: None, value: IlValue::Expr(expr) }
    }

    pub fn try_get_text(&self) -> Option<&str> {
        match &self.value {
            IlValue::Text(t) => Some(t),
            _ => None,
        }
    }
}

// ── IL instruction ──

#[derive(Clone, Debug)]
pub struct IlInstruction {
    pub offset: usize,
    pub end: usize,
    pub mnemonic: String,
    pub operands: Vec<IlOperand>,
    pub comments: Vec<String>,
}

impl IlInstruction {
    pub fn new(offset: usize, end: usize, mnemonic: impl Into<String>) -> Self {
        Self {
            offset,
            end,
            mnemonic: mnemonic.into(),
            operands: Vec::new(),
            comments: Vec::new(),
        }
    }

    pub fn get_operand_value(&self, name: &str) -> Option<&str> {
        self.operands.iter().find(|o| o.name.as_deref() == Some(name)).and_then(|o| o.try_get_text())
    }
}

// ── IL document ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IlDocumentKind {
    Scx,
    Msb,
}

pub struct IlDocument {
    pub kind: IlDocumentKind,
    pub source_path: String,
    pub size: usize,
    pub off_table1: u32,
    pub off_table2: u32,
    pub code_start: usize,
    pub code_end: usize,
    pub sweep_start: usize,
    pub msb_source_set: Option<String>,
    pub msb_raw_tail: Option<Vec<u8>>,
    pub instructions: std::collections::BTreeMap<usize, IlInstruction>,
}

// ── emit helpers ──

pub fn emit(offset: usize, end: usize, mnemonic: &str, operands: Vec<IlOperand>) -> IlInstruction {
    IlInstruction {
        offset,
        end,
        mnemonic: mnemonic.to_ascii_lowercase(),
        operands,
        comments: Vec::new(),
    }
}

// ── text renderer ──

pub fn render_document(doc: &IlDocument) -> Vec<String> {
    let mut lines = match doc.kind {
        IlDocumentKind::Scx => render_scx_header(doc),
        IlDocumentKind::Msb => render_msb_header(doc),
    };

    let mut previous_end: Option<usize> = None;
    for (&_off, inst) in &doc.instructions {
        if let Some(prev) = previous_end {
            if inst.offset > prev {
                lines.push(String::new());
            }
        }
        lines.push(format!("{:08X}: {}", inst.offset, render_instruction(inst)));
        previous_end = Some(inst.end);
    }

    lines
}

fn render_scx_header(doc: &IlDocument) -> Vec<String> {
    vec![
        format!("; file={}", doc.source_path),
        format!("; size={} (0x{:X})", doc.size, doc.size),
        "; magic=SC3\\0".into(),
        format!("; off_table1=0x{:X}", doc.off_table1),
        format!("; off_table2=0x{:X}", doc.off_table2),
        format!("; code_region=[0x{:X}, 0x{:X})", doc.code_start, doc.code_end),
        format!("; sweep_start=0x{:X}", doc.sweep_start),
        String::new(),
    ]
}

fn render_msb_header(doc: &IlDocument) -> Vec<String> {
    let mut lines = vec![
        format!("; file={}", doc.source_path),
        format!("; source_set={}", doc.msb_source_set.as_deref().unwrap_or("")),
        format!("; size={} (0x{:X})", doc.size, doc.size),
        "; magic=MES\\0".into(),
        "; version=1".into(),
        format!("; count_field={}", doc.instructions.len()),
        format!("; entry_count={}", doc.instructions.len()),
        format!("; data_offset=0x{:X}", doc.code_start),
        "; layout=count_field relative start offsets; each message ends at next start or EOF".into(),
        "; token_lexer=0x80..0xFE => 4-byte token | 0x00..0x7F => ctrl | 0xFF => end".into(),
        "; decode_policy=bn_semantics_conservative".into(),
    ];
    render_msb_raw_tail(&mut lines, doc.msb_raw_tail.as_deref());
    lines.push(String::new());
    lines
}

fn render_msb_raw_tail(lines: &mut Vec<String>, raw_tail: Option<&[u8]>) {
    let Some(tail) = raw_tail else { return };
    if tail.is_empty() {
        return;
    }
    if tail.len() <= 0x20 {
        lines.push(format!("; raw_tail={}", crate::format::format_hex(tail)));
    } else {
        lines.push(format!("; raw_tail_len=0x{:X}", tail.len()));
        lines.push(format!("; raw_tail_preview={} ...", crate::format::format_hex(&tail[..0x20])));
    }
}

pub fn render_instruction(inst: &IlInstruction) -> String {
    // Special case: expr instruction with a single unnamed expr operand
    if inst.mnemonic == "expr" && inst.operands.len() == 1 && inst.operands[0].name.is_none() {
        if let IlValue::Expr(ref ev) = inst.operands[0].value {
            let mut text = render_expr(ev);
            if !inst.comments.is_empty() {
                text.push_str(&format!(" ; {}", inst.comments.join(" | ")));
            }
            return text;
        }
    }

    let operands_str = inst.operands.iter().map(render_operand).collect::<Vec<_>>().join(", ");
    let mut text = format!("{}({})", inst.mnemonic, operands_str);
    if !inst.comments.is_empty() {
        text.push_str(&format!(" ; {}", inst.comments.join(" | ")));
    }
    text
}

fn render_operand(op: &IlOperand) -> String {
    let value = match &op.value {
        IlValue::Text(t) => t.clone(),
        IlValue::Expr(e) => render_expr(e),
    };
    match &op.name {
        Some(n) => format!("{n}={value}"),
        None => value,
    }
}
