use std::collections::HashMap;

use sleigh_rs::disassembly;
use sleigh_rs::pattern::*;
use sleigh_rs::table::*;
use sleigh_rs::*;
//use sleigh_rs::disassembly::*;
//use sleigh_rs::token::*;
//use sleigh_rs::space::*;

pub use sleigh_rs::file_to_sleigh;

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

pub struct InstructionMatch {
    pub len: usize,
    pub entry: Matcher,
}

pub fn match_instruction(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
) -> Option<InstructionMatch> {
    match_constructor(
        sleigh_data,
        context,
        addr,
        instr,
        sleigh_data.instruction_table,
    )
    .map(|(entry, len)| InstructionMatch { len, entry })
}

fn match_constructor(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
    table_id: TableId,
) -> Option<(Matcher, usize)> {
    let table = sleigh_data.table(table_id);
    table.matcher_order().iter().copied().find_map(|entry| {
        let constructor = table.constructor(entry.constructor);
        let (context_bits, pattern_bits) = constructor.variant(entry.variant_id);
        if !match_contraint_bits(context, context_bits)
            || !match_contraint_bits(instr, pattern_bits)
        {
            return None;
        }
        match_pattern(
            sleigh_data,
            context,
            addr,
            instr,
            table,
            entry,
            &constructor.pattern,
        )
        .map(|len| (entry, len))
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
) -> Option<usize> {
    let context_old = context.to_vec();
    let Some(len) = match_blocks(
        sleigh_data,
        context,
        addr,
        instr,
        table,
        entry,
        pattern.blocks(),
    ) else {
        // restore the context
        context.copy_from_slice(&context_old);
        return None;
    };
    Some(len)
}

fn match_blocks(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    mut addr: u64,
    mut instr: &[u8],
    table: &Table,
    entry: Matcher,
    blocks: &[Block],
) -> Option<usize> {
    let mut len = 0;
    for block in blocks {
        let Some(block_len) = match_block(sleigh_data, context, addr, instr, table, entry, block)
        else {
            return None;
        };
        len += block_len;
        addr += u64::try_from(block_len).unwrap();
        instr = &instr[block_len..];
    }
    Some(len)
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
            token_fields: _,
            tables: _,
            verifications,
            pre: _,
            pos: _,
            variants_prior: _,
            variants_number: _,
        } => {
            let min_len = usize::try_from(len.min()).unwrap();
            verifications.iter().try_fold(min_len, |acc, ver| {
                match_verification(sleigh_data, context, addr, instr, table, entry, block, ver)
                    .map(|len| len.max(acc))
            })
        }
        Block::Or {
            len,
            token_fields: _,
            tables: _,
            branches,
            pos: _,
            variants_prior: _,
            variants_number: _,
        } => {
            let min_len = usize::try_from(len.min()).unwrap();
            // all branches should be of the saze len, but check it just in case
            let len = branches.iter().find_map(|ver| {
                match_verification(sleigh_data, context, addr, instr, table, entry, block, ver)
            })?;
            Some(len.max(min_len))
        }
    }
}

fn match_verification(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
    table: &Table,
    entry: Matcher,
    _block: &Block,
    verification: &Verification,
) -> Option<usize> {
    use Verification::*;
    match verification {
        ContextCheck {
            context: field,
            op,
            value: other,
        } => {
            let value = get_context_field(sleigh_data, context, *field);
            let other = eval_disassembly_expr_value(
                sleigh_data,
                context,
                addr,
                instr,
                table,
                entry,
                other.expr(),
            );
            verify_cmp_ops(value, *op, other).then_some(0)
        }
        TableBuild {
            produced_table,
            verification: None,
        } => {
            let constructor =
                match_constructor(sleigh_data, context, addr, instr, produced_table.table);
            constructor.map(|(_entry, len)| len)
        }
        TableBuild {
            produced_table: _,
            verification: Some(_),
        } => todo!(),
        TokenFieldCheck {
            field,
            op,
            value: other,
        } => {
            let value = get_token_field(sleigh_data, instr, *field);
            let other = eval_disassembly_expr_value(
                sleigh_data,
                context,
                addr,
                instr,
                table,
                entry,
                other.expr(),
            );
            verify_cmp_ops(value, *op, other).then(|| {
                let token_field = sleigh_data.token_field(*field);
                let token = sleigh_data.token(token_field.token);
                usize::try_from(token.len_bytes.get()).unwrap()
            })
        }
        SubPattern {
            location: _,
            pattern,
        } => match_pattern(sleigh_data, context, addr, instr, table, entry, pattern),
    }
}

fn eval_disassembly_expr_value(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    addr: u64,
    instr: &[u8],
    _table: &Table,
    _entry: Matcher,
    expr: &disassembly::Expr,
) -> i128 {
    use disassembly::ExprElement::*;
    let (last, mut expr) = expr.elements().split_last().unwrap();
    let Value {
        value: last,
        location: _,
    } = last
    else {
        panic!("invalid expr");
    };
    let mut acc = eval_disassembly_read_scope(sleigh_data, context, addr, instr, *last);
    // unstack until empty
    loop {
        let Some((a, rest)) = expr.split_last() else {
            // no more elements, finished the eval
            return acc;
        };
        expr = rest;
        if let OpUnary(unary) = a {
            acc = eval_disassembly_unary_op(*unary, acc);
            continue;
        }
        let (b, rest) = rest.split_last().unwrap();
        expr = rest;
        if let (Op(op), Value { value: b, .. }) = (b, a) {
            let value = eval_disassembly_read_scope(sleigh_data, context, addr, instr, *b);
            acc = eval_disassembly_binary_op(*op, value, acc);
            continue;
        }
        panic!("invalid expr");
    }
}

fn eval_disassembly_read_scope(
    sleigh_data: &Sleigh,
    context: &[u8],
    addr: u64,
    instr: &[u8],
    value: disassembly::ReadScope,
) -> i128 {
    use disassembly::ReadScope::*;
    match value {
        Integer(value) => value.signed_super(),
        Context(field_id) => get_context_field(sleigh_data, context, field_id),
        TokenField(field_id) => get_token_field(sleigh_data, instr, field_id),
        InstStart(_) => addr.into(),
        InstNext(_) => panic!("inst_next in disassembly context"),
        Local(_) => todo!(),
    }
}

fn eval_disassembly_unary_op(unary: disassembly::OpUnary, value: i128) -> i128 {
    match unary {
        disassembly::OpUnary::Negation => (value == 0).into(),
        disassembly::OpUnary::Negative => -value,
    }
}

fn eval_disassembly_binary_op(op: disassembly::Op, value: i128, other: i128) -> i128 {
    // TODO implement overflow
    match op {
        disassembly::Op::Add => value + other,
        disassembly::Op::Sub => value - other,
        disassembly::Op::Mul => value * other,
        disassembly::Op::Div => value / other,
        disassembly::Op::And => value & other,
        disassembly::Op::Or => value | other,
        disassembly::Op::Xor => value ^ other,
        disassembly::Op::Asr => value >> other,
        disassembly::Op::Lsl => value << other,
    }
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
