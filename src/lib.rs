use std::collections::HashMap;
use std::fmt::Write;

use sleigh_rs::disassembly;
use sleigh_rs::disassembly::Assertation;
use sleigh_rs::disassembly::*;
use sleigh_rs::pattern::*;
use sleigh_rs::table::*;
use sleigh_rs::*;
//use sleigh_rs::token::*;
//use sleigh_rs::space::*;

pub use sleigh_rs::file_to_sleigh;

pub type GlobalSetContext = HashMap<(u64, ContextId), i128>;

#[derive(Debug, Clone)]
pub struct InstructionMatch {
    pub constructor: ConstructorMatch,
    pub global_set: GlobalSetContext,
    pub context: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConstructorMatch {
    pub len: usize,
    pub table_id: TableId,
    pub entry: Matcher,
    pub token_fields: HashMap<TokenFieldId, i128>,
    pub sub_tables: HashMap<TableId, ConstructorMatch>,
    pub disassembly_vars: HashMap<disassembly::VariableId, i128>,
}

impl ConstructorMatch {
    fn new(table_id: TableId, entry: Matcher) -> Self {
        Self {
            len: 0,
            table_id,
            entry,
            token_fields: Default::default(),
            sub_tables: Default::default(),
            disassembly_vars: Default::default(),
        }
    }
}

pub fn new_default_context(sleigh_data: &Sleigh) -> Vec<u8> {
    let bits = sleigh_data.context_memory.memory_bits;
    let bytes = usize::try_from((bits + 7) / 8).unwrap();
    vec![0; bytes]
}

pub fn to_string_instruction(
    sleigh_data: &Sleigh,
    context: &[u8],
    addr: u64,
    instruction: &InstructionMatch,
) -> String {
    let mut output = String::new();
    to_string_constructor(
        sleigh_data,
        context,
        addr,
        sleigh_data.instruction_table(),
        &instruction.constructor,
        &mut output,
    );
    output
}

pub fn to_string_constructor(
    sleigh_data: &Sleigh,
    context: &[u8],
    inst_start: u64,
    table: TableId,
    matched: &ConstructorMatch,
    output: &mut String,
) {
    use display::DisplayElement::*;
    let table = sleigh_data.table(table);
    let constructor = table.constructor(matched.entry.constructor);
    if let Some(mneu) = &constructor.display.mneumonic {
        output.push_str(mneu);
    }
    for element in constructor.display.elements() {
        match element {
            Varnode(varnode) => {
                let varnode = sleigh_data.varnode(*varnode);
                output.push_str(varnode.name());
            }
            Context(var) => {
                get_context_field_name(sleigh_data, context, *var, output);
            }
            TokenField(var) => {
                get_token_field_name(sleigh_data, matched, *var, output);
            }
            InstStart(_) => write!(output, "{inst_start:#x}").unwrap(),
            InstNext(_) => write!(
                output,
                "{:#x}",
                inst_start + u64::try_from(matched.len).unwrap()
            )
            .unwrap(),
            Table(sub_table) => {
                let matched_sub_table = matched.sub_tables.get(sub_table).unwrap();
                to_string_constructor(
                    sleigh_data,
                    context,
                    inst_start,
                    *sub_table,
                    matched_sub_table,
                    output,
                );
            }
            Disassembly(var) => {
                let value = matched
                    .disassembly_vars
                    .get(var)
                    .copied()
                    .unwrap_or_else(|| {
                        let name = table
                            .constructor(matched.entry.constructor)
                            .pattern
                            .disassembly_var(*var)
                            .name();
                        panic!("Variable {name} not found")
                    });
                // HACK: calculated values are always interpreted as i64
                let value = if value > i128::from(u64::MAX) {
                    todo!("disassembly is greater then u64 just truncate it?");
                } else {
                    i128::from(value as i64)
                };
                if value < 0 {
                    write!(output, "-{:#x}", value.abs()).unwrap();
                } else {
                    write!(output, "{value:#x}").unwrap();
                }
            }
            Literal(lit) => output.push_str(lit),
            Space => output.push(' '),
        }
    }
}

pub fn match_instruction(
    sleigh_data: &Sleigh,
    context: Vec<u8>,
    inst_start: u64,
    instr: &[u8],
) -> Option<InstructionMatch> {
    let ctx = InstructionMatchCtx::find(sleigh_data, context, inst_start, instr);
    Some(InstructionMatch {
        constructor: ctx.constructor?,
        global_set: ctx.global_set,
        context: ctx.context,
    })
}

struct InstructionMatchCtx<'a> {
    sleigh_data: &'a Sleigh,
    context: Vec<u8>,
    inst_start: u64,
    inst: &'a [u8],
    global_set: HashMap<(u64, ContextId), i128>,
    constructor: Option<ConstructorMatch>,
}

impl<'a> InstructionMatchCtx<'a> {
    fn find(sleigh_data: &'a Sleigh, context: Vec<u8>, inst_start: u64, inst: &'a [u8]) -> Self {
        let mut ctx = Self {
            sleigh_data,
            context,
            inst_start,
            inst,
            global_set: Default::default(),
            constructor: None,
        };
        // match a construction (AKA instruction) from the root table (AKA
        // instructions)
        if let Some(mut found) =
            ConstructorMatchCtx::find(&mut ctx, sleigh_data.instruction_table(), inst)
        {
            // found the constructor, AKA instruction, do the post disassembly
            let inst_len = u64::try_from(found.matched.len).unwrap();
            found
                .inst_ctx
                .post_disassembly_constructor(&mut found.matched, inst_start + inst_len);
            ctx.constructor = Some(found.matched);
        }
        ctx
    }
}

struct ConstructorMatchCtx<'a, 'b> {
    inst_ctx: &'b mut InstructionMatchCtx<'a>,
    table_id: TableId,
    inst_current: &'a [u8],
    matched: ConstructorMatch,
}

impl<'a, 'b> ConstructorMatchCtx<'a, 'b> {
    fn table(&self) -> &'a Table {
        self.inst_ctx.sleigh_data.table(self.table_id)
    }

    fn constructor(&self) -> &'a Constructor {
        self.table().constructor(self.matched.entry.constructor)
    }

    fn find(
        inst_ctx: &'b mut InstructionMatchCtx<'a>,
        table_id: TableId,
        inst_current: &'a [u8],
    ) -> Option<Self> {
        // find a entry that match the current inst
        let matcher_order = inst_ctx.sleigh_data.table(table_id).matcher_order();
        let mut ctx = Self {
            inst_ctx,
            table_id,
            inst_current,
            // NOTE: dummy value
            matched: ConstructorMatch::new(table_id, *matcher_order.first()?),
        };
        for entry in matcher_order {
            // clean the `ctx` before each loop, AKA backtrack
            ctx.inst_current = inst_current;
            ctx.matched = ConstructorMatch::new(table_id, *entry);

            let (context_bits, pattern_bits) = ctx.constructor().variant(entry.variant_id);
            if match_contraint_bits(&ctx.inst_ctx.context, context_bits)
                && match_contraint_bits(ctx.inst_current, pattern_bits)
            {
                if let Some(len) = ctx.match_blocks(ctx.constructor().pattern.blocks()) {
                    ctx.matched.len = len;
                    return Some(ctx);
                }
            }
        }
        None
    }

    // TODO based on the entry number, only verify the corresponding branches
    // from the pattern
    fn match_blocks(&mut self, blocks: &'a [Block]) -> Option<usize> {
        let context_old = self.inst_ctx.context.clone();
        let global_set_old = self.inst_ctx.global_set.clone();
        let mut len = 0;
        for block in blocks {
            let Some(block_len) = self.match_block(block) else {
                // restore the context
                self.inst_ctx.context = context_old;
                self.inst_ctx.global_set = global_set_old;
                return None;
            };
            len += block_len;
            self.inst_current = &self.inst_current[block_len..];
        }
        Some(len)
    }

    fn match_block(&mut self, block: &'a Block) -> Option<usize> {
        // TODO find the right branch in OR-BLOCKS based on the variant number
        if u64::try_from(self.inst_current.len()).unwrap() < block.len().min() {
            return None;
        }
        match block {
            Block::And {
                len,
                token_fields,
                // tables are pipulated during the verifications phase
                tables: _,
                verifications,
                pre,
                pos: _,
                variants_prior: _,
                variants_number: _,
            } => {
                let min_len = usize::try_from(len.min()).unwrap();
                let len = verifications.iter().try_fold(min_len, |acc, ver| {
                    self.match_verification(ver).map(|len| len.max(acc))
                })?;
                self.populate_token_fields(token_fields);
                let inst_current = self.inst_current;
                self.inst_ctx.eval_assertations(
                    &mut self.matched,
                    None, // instruction len was not calculated yet
                    inst_current,
                    pre,
                );
                Some(len)
            }
            Block::Or {
                len,
                token_fields,
                // tables are pipulated during the verifications phase
                tables: _,
                branches,
                pos: _,
                variants_prior: _,
                variants_number: _,
            } => {
                let min_len = usize::try_from(len.min()).unwrap();
                // all branches should be of the saze len, but check it just in case
                let len = branches
                    .iter()
                    .find_map(|ver| self.match_verification(ver))?;
                self.populate_token_fields(token_fields);
                Some(len.max(min_len))
            }
        }
    }

    fn match_verification(&mut self, verification: &'a Verification) -> Option<usize> {
        use Verification::*;
        match verification {
            ContextCheck {
                context: field,
                op,
                value: other,
            } => {
                let value = get_context_field_value(
                    self.inst_ctx.sleigh_data,
                    &self.inst_ctx.context,
                    *field,
                );
                let other = eval_disassembly_expr_value(
                    self.inst_ctx.sleigh_data,
                    &mut self.inst_ctx.context,
                    self.inst_ctx.inst_start,
                    None,
                    self.inst_ctx.inst,
                    other.expr(),
                    None,
                );
                verify_cmp_ops(value, *op, other).then_some(0)
            }
            TableBuild {
                produced_table,
                verification: None,
            } => {
                let constructor_ctx = ConstructorMatchCtx::find(
                    self.inst_ctx,
                    produced_table.table,
                    self.inst_current,
                )?;
                let len = constructor_ctx.matched.len;
                if let Some(_old_constructor_match) = self
                    .matched
                    .sub_tables
                    .insert(produced_table.table, constructor_ctx.matched)
                {
                    panic!("Table produced multiple times");
                }
                Some(len)
            }
            TableBuild {
                produced_table: _,
                verification: Some(_),
            } => todo!("Build sub-tables with verification"),
            TokenFieldCheck {
                field,
                op,
                value: other,
            } => {
                let value =
                    get_token_field_value(self.inst_ctx.sleigh_data, self.inst_current, *field);
                let other = eval_disassembly_expr_value(
                    self.inst_ctx.sleigh_data,
                    &mut self.inst_ctx.context,
                    self.inst_ctx.inst_start,
                    None,
                    self.inst_ctx.inst,
                    other.expr(),
                    None,
                );
                verify_cmp_ops(value, *op, other).then(|| {
                    let token_field = self.inst_ctx.sleigh_data.token_field(*field);
                    let token = self.inst_ctx.sleigh_data.token(token_field.token);
                    usize::try_from(token.len_bytes.get()).unwrap()
                })
            }
            SubPattern {
                location: _,
                pattern,
            } => {
                // subpatterns don't advance the inst offset, so revert it
                let instr_old = self.inst_current;
                let len = self.match_blocks(pattern.blocks())?;
                self.inst_current = instr_old;
                Some(len)
            }
        }
    }

    fn populate_token_fields(&mut self, token_fields: &'a [ProducedTokenField]) {
        for prod_token_field in token_fields {
            let field = prod_token_field.field;
            let value =
                get_token_field_raw_value(self.inst_ctx.sleigh_data, self.inst_current, field);
            if let Some(_old_token_field) = self.matched.token_fields.insert(field, value) {
                panic!("Token Field produced multiple times");
            }
        }
    }
}

fn eval_disassembly_expr_value(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    inst_start: u64,
    inst_next: Option<u64>,
    instr: &[u8],
    expr: &disassembly::Expr,
    constructor_match: Option<&ConstructorMatch>,
) -> i128 {
    use disassembly::ExprElement::*;
    let elements = expr.elements();
    let mut buffer: Vec<_> = elements.iter().rev().cloned().collect();
    loop {
        let (result, location) = match buffer[..] {
            // if is a single value, just return it
            [Value { value, .. }] => {
                return eval_disassembly_read_scope(
                    sleigh_data,
                    context,
                    inst_start,
                    inst_next,
                    instr,
                    value,
                    constructor_match,
                );
            }
            [.., OpUnary(_), Value { .. }] => {
                let value = buffer.pop().unwrap();
                let op = buffer.pop().unwrap();
                let (OpUnary(op), Value { value, location }) = (op, value) else {
                    unreachable!();
                };
                let value = eval_disassembly_read_scope(
                    sleigh_data,
                    context,
                    inst_start,
                    inst_next,
                    instr,
                    value,
                    constructor_match,
                );
                let value = eval_disassembly_unary_op(op, value);
                (value, location)
            }
            [.., Op(_), Value { .. }, Value { .. }] => {
                let left = buffer.pop().unwrap();
                let right = buffer.pop().unwrap();
                let op = buffer.pop().unwrap();
                let (
                    Op(op),
                    Value {
                        value: left,
                        location,
                    },
                    Value {
                        value: right,
                        location: _,
                    },
                ) = (op, left, right)
                else {
                    unreachable!();
                };
                let left = eval_disassembly_read_scope(
                    sleigh_data,
                    context,
                    inst_start,
                    inst_next,
                    instr,
                    left,
                    constructor_match,
                );
                let right = eval_disassembly_read_scope(
                    sleigh_data,
                    context,
                    inst_start,
                    inst_next,
                    instr,
                    right,
                    constructor_match,
                );
                let value = eval_disassembly_binary_op(op, left, right);
                (value, location)
            }
            _ => panic!("invalid expr"),
        };
        let number = if result < 0 {
            Number::Negative((-result).try_into().unwrap())
        } else {
            Number::Positive(result.try_into().unwrap())
        };
        buffer.push(ExprElement::Value {
            value: ReadScope::Integer(number),
            location,
        });
    }
}

fn eval_disassembly_read_scope(
    sleigh_data: &Sleigh,
    context: &[u8],
    inst_start: u64,
    inst_next: Option<u64>,
    instr: &[u8],
    value: disassembly::ReadScope,
    constructor_match: Option<&ConstructorMatch>,
) -> i128 {
    use disassembly::ReadScope::*;
    match value {
        Integer(value) => value.signed_super(),
        Context(field_id) => get_context_field_value(sleigh_data, context, field_id),
        TokenField(field_id) => {
            if let Some(constructor_match) = constructor_match {
                // if we already matched and we are populating the token_fields
                let value = *constructor_match.token_fields.get(&field_id).unwrap();
                get_token_field_translate_value(sleigh_data, field_id, value)
            } else {
                // in the matched step, not populating yet
                get_token_field_value(sleigh_data, instr, field_id)
            }
        }
        InstStart(_) => inst_start.into(),
        InstNext(_) => inst_next.unwrap().into(),
        Local(var) => *constructor_match
            .as_ref()
            .unwrap()
            .disassembly_vars
            .get(&var)
            .unwrap(),
    }
}

fn eval_disassembly_unary_op(unary: disassembly::OpUnary, value: i128) -> i128 {
    match unary {
        disassembly::OpUnary::Negation => !value,
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

impl<'a> InstructionMatchCtx<'a> {
    fn eval_assertations(
        &mut self,
        const_match: &mut ConstructorMatch,
        inst_next: Option<u64>,
        instr: &[u8],
        assertations: &[Assertation],
    ) {
        for ass in assertations {
            match ass {
                Assertation::GlobalSet(GlobalSet {
                    address,
                    context: context_id,
                    ..
                }) => {
                    let value_addr =
                        eval_address_scope(self.inst_start, inst_next, address, const_match);
                    let value =
                        get_context_field_value(self.sleigh_data, &self.context, *context_id);
                    if let Some(_old_global_set) =
                        self.global_set.insert((value_addr, *context_id), value)
                    {
                        todo!("Same GlobalSet is done twice");
                    };
                }
                Assertation::Assignment(Assignment { left, right }) => {
                    let value = eval_disassembly_expr_value(
                        self.sleigh_data,
                        &mut self.context,
                        self.inst_start,
                        inst_next,
                        instr,
                        right,
                        Some(const_match),
                    );
                    match left {
                        WriteScope::Context(context_id) => {
                            set_context_field_value(
                                self.sleigh_data,
                                &mut self.context,
                                *context_id,
                                value as u128,
                            );
                        }
                        WriteScope::Local(var) => {
                            let var = const_match.disassembly_vars.entry(*var).or_default();
                            *var = value;
                        }
                    }
                }
            }
        }
    }
}

fn eval_address_scope(
    inst_start: u64,
    inst_next: Option<u64>,
    address_scope: &AddrScope,
    constructor_match: &ConstructorMatch,
) -> u64 {
    match address_scope {
        AddrScope::Integer(value) => *value,
        AddrScope::Table(_) => todo!("exported table value in disassembly"),
        AddrScope::InstStart(_) => inst_start,
        AddrScope::InstNext(_) => inst_next.unwrap(),
        AddrScope::Local(var) => {
            let var = constructor_match.disassembly_vars.get(var).unwrap();
            u64::try_from(*var).unwrap()
        }
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

// TODO use the array directly, avoid converting into int
fn bits_from_array<const BE: bool>(array: &[u8]) -> u128 {
    match array.len() {
        0 => 0u128,
        1 => array[0].into(),
        2 => {
            if BE {
                u16::from_be_bytes(array.try_into().unwrap()).into()
            } else {
                u16::from_le_bytes(array.try_into().unwrap()).into()
            }
        }
        4 => {
            if BE {
                u32::from_be_bytes(array.try_into().unwrap()).into()
            } else {
                u32::from_le_bytes(array.try_into().unwrap()).into()
            }
        }
        8 => {
            if BE {
                u64::from_be_bytes(array.try_into().unwrap()).into()
            } else {
                u64::from_le_bytes(array.try_into().unwrap()).into()
            }
        }
        16 => {
            if BE {
                u128::from_be_bytes(array.try_into().unwrap())
            } else {
                u128::from_le_bytes(array.try_into().unwrap())
            }
        }
        bytes @ (..=16) => {
            let mut value = [0; 16];
            if BE {
                value[16 - bytes..].copy_from_slice(array);
                u128::from_be_bytes(value)
            } else {
                value[..bytes].copy_from_slice(array);
                u128::from_le_bytes(value)
            }
        }
        _ => panic!("context is too big"),
    }
}

pub fn get_context_field_value(sleigh_data: &Sleigh, context: &[u8], field_id: ContextId) -> i128 {
    // TODO solve the meaning if any, like in token field
    let field = sleigh_data.context(field_id);
    let range = &field.bitrange.bits;
    // context have the bits inverted, for reasons...
    let bits = bits_from_array::<false>(context).reverse_bits();
    let len = u32::try_from(range.len().get()).unwrap();
    let start = u64::from(u128::BITS - len) - range.start();
    let mask = u128::MAX >> (u128::BITS - len);
    let bits = (bits >> start) & mask;
    if field.is_signed() {
        let signed_bit = 1 << (len - 1);
        if (bits & signed_bit) != 0 {
            (bits | !mask) as i128
        } else {
            bits as i128
        }
    } else {
        bits as i128
    }
}

pub fn get_context_field_name(
    sleigh_data: &Sleigh,
    context: &[u8],
    var: ContextId,
    output: &mut String,
) {
    // TODO solve the meaning if any, like in token field
    let value = get_context_field_value(sleigh_data, context, var);
    write!(output, "{value:#x}").unwrap();
}

pub fn set_context_field_value(
    sleigh_data: &Sleigh,
    context: &mut [u8],
    field_id: ContextId,
    value: u128,
) {
    let field = sleigh_data.context(field_id);
    let range = &field.bitrange.bits;
    let context_value = bits_from_array::<false>(context).reverse_bits();
    let len = u32::try_from(range.len().get()).unwrap();
    let start = u64::from(u128::BITS - len) - range.start();
    let mask = u128::MAX >> (u128::BITS - len);
    let value_mask = mask << start;
    let final_context = (context_value & !value_mask) | (value << start);
    let final_context_array = final_context.reverse_bits().to_le_bytes();
    context.copy_from_slice(&final_context_array[..context.len()]);
}

fn get_token_field_raw_value(sleigh_data: &Sleigh, inst: &[u8], field_id: TokenFieldId) -> i128 {
    let field = sleigh_data.token_field(field_id);
    let token = sleigh_data.token(field.token);
    let range = &field.bits;
    let len_bytes = usize::try_from(token.len_bytes.get()).unwrap();
    let inst_token = inst.get(0..len_bytes).unwrap();
    let start = range.start();
    let len = u32::try_from(range.len().get()).unwrap();
    let bits = if token.endian().is_big() {
        bits_from_array::<true>(inst_token)
    } else {
        bits_from_array::<false>(inst_token)
    };
    let bits = (bits >> start) & (u128::MAX >> (u128::BITS - len));
    if let meaning::Meaning::NoAttach(ValueFmt {
        signed: true,
        base: _,
    }) = field.meaning()
    {
        let body_bits = u32::try_from(range.len().get() - 1).unwrap();
        let signed_bit = 1 << body_bits;
        let body = bits & !signed_bit;
        let signed = bits & signed_bit;
        if signed != 0 {
            let mask = u128::MAX >> (u128::BITS - body_bits);
            return (body | !mask) as i128;
        }
    }
    bits as i128
}

fn get_token_field_translate_value(
    sleigh_data: &Sleigh,
    field_id: TokenFieldId,
    bits: i128,
) -> i128 {
    let field = sleigh_data.token_field(field_id);
    if let meaning::Meaning::Number(_base, values) = field.meaning() {
        let values = sleigh_data.attach_number(values);
        let bits = usize::try_from(bits).unwrap();
        return values
            .0
            .iter()
            .find_map(|(idx, value)| (*idx == bits).then_some(value))
            .unwrap()
            .signed_super();
    }
    bits
}

fn get_token_field_value(sleigh_data: &Sleigh, inst: &[u8], field_id: TokenFieldId) -> i128 {
    let bits = get_token_field_raw_value(sleigh_data, inst, field_id);
    get_token_field_translate_value(sleigh_data, field_id, bits)
}

fn get_token_field_name(
    sleigh_data: &Sleigh,
    matched: &ConstructorMatch,
    var: TokenFieldId,
    output: &mut String,
) {
    let field = sleigh_data.token_field(var);
    let raw_value = matched.token_fields.get(&var).unwrap();
    let value = get_token_field_translate_value(sleigh_data, var, *raw_value);
    match field.meaning() {
        meaning::Meaning::NoAttach(_) => {
            // HACK: it seems that the attach signed flag is ignored, and the
            // value is always printed as an i64
            let value = if value > i128::from(u64::MAX) {
                todo!("token field is greater then u64 just truncate it?");
            } else {
                i128::from(value as i64)
            };
            if value < 0 {
                write!(output, "-{:#x}", value.abs()).unwrap();
            } else {
                write!(output, "{value:#x}").unwrap();
            }
        }
        meaning::Meaning::Varnode(vars) => {
            let vars = sleigh_data.attach_varnode(vars);
            let (_, var) = vars
                .0
                .iter()
                .find(|(id, _var)| *id == usize::try_from(value).unwrap())
                .unwrap();
            let varnode = sleigh_data.varnode(*var);
            output.push_str(varnode.name());
        }
        meaning::Meaning::Literal(lits) => {
            let lits = sleigh_data.attach_literal(lits);
            let (_, lit) = lits
                .0
                .iter()
                .find(|(id, _var)| *id == usize::try_from(value).unwrap())
                .unwrap();
            output.push_str(lit);
        }
        // already translated by get_token_field_translate_value
        meaning::Meaning::Number(base, _values) => match base {
            PrintBase::Dec => write!(output, "{value}").unwrap(),
            PrintBase::Hex => write!(output, "{value:#x}").unwrap(),
        },
    }
}

// disassembly assertations that need to run after the instruction have being
// fully matched, mostly because they depend on instr_next
impl<'a> InstructionMatchCtx<'a> {
    fn post_disassembly_constructor(&mut self, const_match: &mut ConstructorMatch, inst_next: u64) {
        // TODO inside-out or outside-in?
        let constructor = self
            .sleigh_data
            .table(const_match.table_id)
            .constructor(const_match.entry.constructor);
        for sub_table in const_match.sub_tables.values_mut() {
            self.post_disassembly_constructor(sub_table, inst_next);
        }
        for block in constructor.pattern.blocks.iter() {
            self.eval_assertations(const_match, Some(inst_next), &[], block.post_disassembler());
        }
        self.eval_assertations(const_match, Some(inst_next), &[], &constructor.pattern.pos);
    }
}
