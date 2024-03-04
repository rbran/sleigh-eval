use std::collections::HashMap;
use std::ops::Range;

use sleigh_rs::disassembly::Expr;
use sleigh_rs::disassembly::ExprElement;
use sleigh_rs::disassembly::ReadScope;
use sleigh_rs::pattern::*;
use sleigh_rs::table::*;
use sleigh_rs::*;
//use sleigh_rs::disassembly::*;
//use sleigh_rs::token::*;
//use sleigh_rs::space::*;

pub use sleigh_rs::file_to_sleigh;

pub struct SleighEval<'a> {
    sleigh_data: &'a Sleigh,
    context: Vec<u8>,
}

impl<'a> SleighEval<'a> {
    pub fn new(sleigh_data: &'a Sleigh) -> Self {
        let context = new_default_context(sleigh_data);
        Self {
            sleigh_data,
            context,
        }
    }

    pub fn parse_instruction(&mut self, addr: u64, instr: &[u8]) -> Option<()> {
        match_instruction(self.sleigh_data, &mut self.context, addr, instr)
    }
}

pub struct TableMatch {
    pub context: Option<Vec<u8>>,
    pub table_id: TableId,
    pub entry: Matcher,
    pub token_fields: HashMap<TokenFieldId, Vec<u8>>,
    pub sub_tables: HashMap<TableId, Matcher>,
}

pub fn new_default_context(sleigh_data: &Sleigh) -> Vec<u8> {
    let bits = sleigh_data.context_memory.memory_bits;
    let bytes = usize::try_from((bits + 7) / 8).unwrap();
    vec![0; bytes]
}

fn get_context_field(sleigh_data: &Sleigh, context: &[u8], field_id: ContextId) -> i128 {
    let field = sleigh_data.context(field_id);
    let range = &field.bitrange.bits;
    let bits = bits_from_array(context, true, range);
    if field.is_signed() {
        let signed_mask = (1 << u32::try_from(range.len().get()).unwrap()) - 1;
        let sb = bits & signed_mask;
        let value = i128::try_from(bits & !signed_mask).unwrap();
        if sb != 0 {
            value.checked_neg().unwrap()
        } else {
            value
        }
    } else {
        bits as i128
    }
}

fn get_token_field(sleigh_data: &Sleigh, inst: &[u8], field_id: TokenFieldId) -> i128 {
    let field = sleigh_data.token_field(field_id);
    let token = sleigh_data.token(field.token);
    let range = &field.bits;
    let inst_token = inst
        .get(0..usize::try_from(token.len_bytes.get()).unwrap())
        .unwrap();
    let bits = bits_from_array(inst_token, false, range);
    bits as i128
}

pub fn match_instruction(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
) -> Option<()> {
    match_constructor(
        sleigh_data,
        context,
        addr,
        instr,
        sleigh_data.instruction_table,
    )
    .map(|_| (/*TODO*/))
}

fn match_constructor(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
    table_id: TableId,
) -> Option<Matcher> {
    let table = sleigh_data.table(table_id);
    table.matcher_order().iter().copied().find(|entry| {
        let constructor = table.constructor(entry.constructor);
        let (context_bits, pattern_bits) = constructor.variant(entry.variant_id);
        if !match_contraint_bits(context, context_bits)
            || !match_contraint_bits(instr, pattern_bits)
        {
            return false;
        }
        match_pattern(
            sleigh_data,
            context,
            addr,
            instr,
            table,
            *entry,
            &constructor.pattern,
        )
    })
}

fn match_pattern(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
    table: &Table,
    entry: Matcher,
    pattern: &Pattern,
) -> bool {
    let context_old = context.to_vec();
    if !match_blocks(
        sleigh_data,
        context,
        addr,
        instr,
        table,
        entry,
        pattern.blocks(),
    ) {
        // restore the context
        context.copy_from_slice(&context_old);
        return false;
    }
    true
}

fn match_blocks(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    mut addr: u64,
    mut instr: &[u8],
    table: &Table,
    entry: Matcher,
    blocks: &[Block],
) -> bool {
    for block in blocks {
        let Some(block_len) = match_block(sleigh_data, context, addr, instr, table, entry, block)
        else {
            return false;
        };
        addr += u64::try_from(block_len).unwrap();
        instr = &instr[block_len..];
    }
    true
}

fn match_block(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
    table: &Table,
    entry: Matcher,
    block: &Block,
) -> Option<usize> {
    // TODO find the right branch in OR-BLOCKS based on the variant number
    if u64::try_from(instr.len()).unwrap() < block.len().min() {
        return None;
    }
    for subtable in block.tables() {
        let _ = match_constructor(sleigh_data, context, addr, instr, subtable.table);
    }
    match block {
        Block::And {
            len,
            token_fields,
            tables: _,
            verifications,
            pre,
            pos,
            variants_prior: _,
            variants_number: _,
        } => {
            if !verifications.iter().all(|ver| {
                match_verification(sleigh_data, context, addr, instr, table, entry, block, ver)
            }) {
                return None;
            }
            if let Some(len) = len.single_len() {
                return Some(usize::try_from(len).unwrap());
            }
            todo!();
        }
        Block::Or {
            len,
            token_fields,
            tables: _,
            branches,
            pos,
            variants_prior: _,
            variants_number: _,
        } => {
            if !branches.iter().any(|ver| {
                match_verification(sleigh_data, context, addr, instr, table, entry, block, ver)
            }) {
                return None;
            }
            if let Some(len) = len.single_len() {
                return Some(usize::try_from(len).unwrap());
            }
            todo!();
        },
    }
}

fn match_verification(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    _addr: u64,
    _instr: &[u8],
    _table: &Table,
    _entry: Matcher,
    _block: &Block,
    verification: &Verification,
) -> bool {
    use Verification::*;
    match verification {
        ContextCheck {
            context: field,
            op,
            value: other,
        } => {
            let value = get_context_field(sleigh_data, context, *field);
            let other = eval_expr_value(
                sleigh_data,
                context,
                _addr,
                _instr,
                _table,
                _entry,
                other.expr(),
            );
            verify_cmp_ops(value, *op, other)
        }
        TableBuild {
            produced_table,
            verification,
        } => todo!(),
        TokenFieldCheck {
            field,
            op,
            value: other,
        } => {
            let value = get_token_field(sleigh_data, _instr, *field);
            let other = eval_expr_value(
                sleigh_data,
                context,
                _addr,
                _instr,
                _table,
                _entry,
                other.expr(),
            );
            verify_cmp_ops(value, *op, other)
        }
        SubPattern {
            location: _,
            pattern,
        } => match_pattern(sleigh_data, context, _addr, _instr, _table, _entry, pattern),
    }
}

fn eval_expr_value(
    _sleigh_data: &Sleigh,
    _context: &mut [u8],
    _addr: u64,
    _instr: &[u8],
    _table: &Table,
    _entry: Matcher,
    _expr: &Expr,
) -> i128 {
    // 99% of the disassembler expressions are just numbers
    if let &[ExprElement::Value {
        value: ReadScope::Integer(value),
        ..
    }] = _expr.elements()
    {
        return value.signed_super();
    }
    todo!();
}

fn verify_cmp_ops(value: i128, op: CmpOp, other: i128) -> bool {
    match op {
        CmpOp::Eq => value == other,
        CmpOp::Ne => value != other,
        CmpOp::Lt => value < other,
        CmpOp::Gt => value > other,
        CmpOp::Le => value <= other,
        CmpOp::Ge => value >= other,
    }
}

fn match_contraint_bits(value: &[u8], constraint: &[BitConstraint]) -> bool {
    use BitConstraint::*;
    // constraint is bigger then the available data
    if value.len() < constraint.len() / 8 {
        return false;
    }
    constraint.iter().enumerate().all(|(bit_i, constr)| {
        let byte_i = bit_i / 8;
        let bit_byte_i = bit_i % 8;
        let value_bit = (value[byte_i] & (1 << bit_byte_i)) != 0;
        match constr {
            // same value, match
            Defined(constr_bit) if *constr_bit == value_bit => true,
            // diferent value, no match
            Defined(_constr_bit) /*if _constr_bit != value_bit*/ => false,
            // no restrictions on bit, match
            Restrained | Unrestrained => true,
        }
    })
}

fn bits_from_array(array: &[u8], reverse: bool, range: &FieldBits) -> u128 {
    let mut value = match array.len() {
        0 => 0u128,
        1 => u8::from_be_bytes(array.try_into().unwrap()).into(),
        2 => u16::from_be_bytes(array.try_into().unwrap()).into(),
        4 => u32::from_be_bytes(array.try_into().unwrap()).into(),
        8 => u64::from_be_bytes(array.try_into().unwrap()).into(),
        bytes @ (3 | 5 | 6 | 7) => {
            let mut value = [0; 16];
            value[16 - bytes..].copy_from_slice(array);
            u128::from_be_bytes(value)
        }
        9..=16 => todo!(),
        _ => panic!("context is too big"),
    };
    if reverse {
        value = value.reverse_bits();
    }
    let start = range.start();
    let len = u32::try_from(range.len().get()).unwrap();
    (value >> start) & (u128::MAX >> (u128::BITS - len))
}
