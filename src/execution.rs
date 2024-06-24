use std::collections::HashMap;

use sleigh_rs::{
    execution::{AssignmentOp, Binary, BranchCall, MemoryLocation, Unary},
    BitrangeId, Number, NumberNonZeroUnsigned, NumberUnsigned, Sleigh, TableId, UserFunctionId,
    VarnodeId,
};

use crate::{ConstructorMatch, InstructionMatch};

#[derive(Clone, Debug)]
pub struct Execution {
    pub delay_slot: u64,
    pub variables: Vec<Variable>,
    pub blocks: Vec<Block>,
}

impl Execution {
    pub fn variable(&self, variable_id: VariableId) -> &Variable {
        &self.variables[variable_id.0]
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub usize);
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VariableId(pub usize);

#[derive(Clone, Debug)]
pub struct Block {
    pub name: Option<Box<str>>,
    pub next: Option<BlockId>,
    pub statements: Vec<Statement>,
}

#[derive(Clone, Debug)]
pub enum Statement {
    CpuBranch(CpuBranch),
    LocalGoto(LocalGoto),
    UserCall(UserCall),
    Assignment(Assignment),
    MemWrite(MemWrite),
}

#[derive(Clone, Debug)]
pub struct CpuBranch {
    pub cond: Option<Expr>,
    pub call: BranchCall,
    pub direct: bool,
    pub dst: Expr,
}

#[derive(Clone, Debug)]
pub struct LocalGoto {
    pub cond: Option<Expr>,
    pub dst: BlockId,
}

#[derive(Clone, Debug)]
pub struct UserCall {
    pub function: UserFunctionId,
    pub params: Vec<Expr>,
}

#[derive(Clone, Debug)]
pub struct Assignment {
    pub var: WriteValue,
    pub op: Option<AssignmentOp>,
    pub right: Expr,
}

#[derive(Clone, Debug)]
pub struct MemWrite {
    pub addr: Expr,
    pub mem: MemoryLocation,
    pub right: Expr,
}

#[derive(Clone, Debug)]
pub enum Expr {
    Value(ExprElement),
    Op(ExprBinaryOp),
}
impl Expr {
    pub fn len_bits(&self, sleigh: &Sleigh, execution: &Execution) -> NumberNonZeroUnsigned {
        match self {
            Expr::Value(value) => value.len_bits(sleigh, execution),
            Expr::Op(op) => op.len_bits,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExprBinaryOp {
    pub len_bits: NumberNonZeroUnsigned,
    pub op: Binary,
    pub left: Box<Expr>,
    pub right: Box<Expr>,
}

#[derive(Clone, Debug)]
pub enum ExprElement {
    Value(ExprValue),
    UserCall(UserCall),
    Op(ExprUnaryOp),
    // TODO
    // New(ExprNew),
    // CPool(ExprCPool),
}
impl ExprElement {
    pub fn len_bits(&self, sleigh: &Sleigh, execution: &Execution) -> NumberNonZeroUnsigned {
        match self {
            ExprElement::Value(value) => value.len_bits(sleigh, execution),
            ExprElement::UserCall(_call) => todo!(),
            ExprElement::Op(op) => op.output_bits,
        }
    }
}

#[derive(Clone, Debug)]
pub enum WriteValue {
    Varnode(VarnodeId),
    Bitrange(BitrangeId),
    Variable(VariableId),
}

#[derive(Clone, Debug)]
pub enum ExprValue {
    Int {
        len_bits: NumberNonZeroUnsigned,
        number: Number,
    },
    Varnode(VarnodeId),
    Bitrange {
        len_bits: NumberNonZeroUnsigned,
        value: BitrangeId,
    },
    ExeVar(VariableId),
}
impl ExprValue {
    pub fn len_bits(&self, sleigh: &Sleigh, execution: &Execution) -> std::num::NonZero<u64> {
        match self {
            ExprValue::Int {
                len_bits: size,
                number: _,
            } => *size,
            ExprValue::Varnode(varnode) => (sleigh.varnode(*varnode).len_bytes.get() * 8)
                .try_into()
                .unwrap(),
            ExprValue::Bitrange {
                len_bits: size,
                value: _,
            } => *size,
            ExprValue::ExeVar(variable) => execution.variables[variable.0].len_bits,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExprUnaryOp {
    pub output_bits: NumberNonZeroUnsigned,
    pub op: Unary,
    pub input: Box<Expr>,
}

#[derive(Clone, Debug)]
pub struct Variable {
    pub name: String,
    pub len_bits: NumberNonZeroUnsigned,
}

pub fn to_execution_instruction(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
) -> Option<Execution> {
    let table = sleigh_data.table(instruction_match.constructor.table_id);
    let instruction = table.constructor(instruction_match.constructor.entry.constructor);
    let mut result = Execution {
        delay_slot: 0,
        variables: vec![],
        // create the entry block, populated later by inline_constructor
        blocks: vec![Block {
            name: None,
            next: None,
            statements: vec![],
        }],
    };
    let Some(execution) = &instruction.execution else {
        return None;
    };
    assert!(!execution.blocks().is_empty());

    let mut delay_slot = None;

    if inline_constructor(
        sleigh_data,
        addr,
        instruction_match,
        &instruction_match.constructor,
        &mut result,
        BlockId(0),
        None,
        &mut delay_slot,
    )
    .is_err()
    {
        return None;
    }
    result.delay_slot = delay_slot.unwrap_or(0);
    Some(result)
}

fn inline_constructor(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    execution: &mut Execution,
    current_block: BlockId,
    variable_export: Option<VariableId>,
    delay_slot: &mut Option<NumberUnsigned>,
) -> Result<(), ()> {
    let var_offset = execution.variables.len();
    let block_offset = execution.blocks.len();

    // add all the variables
    let sleigh_table = sleigh_data.table(constructor_match.table_id);
    let sleigh_constructor = sleigh_table.constructor(constructor_match.entry.constructor);
    let Some(sleigh_execution) = &sleigh_constructor.execution else {
        return Err(());
    };
    execution
        .variables
        .extend(sleigh_execution.variables().iter().map(|var| Variable {
            name: var.name().to_string(),
            len_bits: var.len_bits,
        }));

    // TODO build sub_tables withough build statements
    let mut table_variable_map: HashMap<TableId, VariableId> = Default::default();

    // create empty blocks, excluding the entry one, the entry block is the block
    // this constructor is being build at
    let first_block = sleigh_execution.blocks().first().unwrap();
    let old_next_block = execution.blocks[current_block.0]
        .next
        .map(|block| BlockId(block.0 + block_offset));
    execution.blocks[current_block.0].next = first_block
        .next
        .map(|block_id| BlockId(block_id.0 + block_offset));
    execution
        .blocks
        .extend(sleigh_execution.blocks().iter().skip(1).map(|block| {
            Block {
                name: block.name.as_ref().map(|name| name.clone()),
                next: block
                    .next
                    .map(|block_id| BlockId(block_id.0 + block_offset))
                    .or(old_next_block),
                statements: vec![],
            }
        }));

    for (sleigh_block, block_id) in sleigh_execution.blocks().iter().zip(block_offset..) {
        for statement in sleigh_block.statements.iter() {
            let new_statement = translate_statement(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                execution,
                &mut table_variable_map,
                var_offset,
                block_offset,
                variable_export,
                delay_slot,
                block_id,
                statement,
            )?;
            if let Some(new_statement) = new_statement {
                execution.blocks[block_id].statements.push(new_statement);
            }
        }
    }

    Ok(())
}

fn translate_statement(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    execution: &mut Execution,
    table_variable_map: &mut HashMap<TableId, VariableId>,
    var_offset: usize,
    block_offset: usize,
    variable_export: Option<VariableId>,
    delay_slot: &mut Option<NumberUnsigned>,
    block_id: usize,
    statement: &sleigh_rs::execution::Statement,
) -> Result<Option<Statement>, ()> {
    Ok(match statement {
        sleigh_rs::execution::Statement::Delayslot(x) => {
            delay_slot
                .replace(*x)
                .map(|_| panic!("multiple delay slot"));
            None
        }
        sleigh_rs::execution::Statement::Export(expr) => Some(Statement::Assignment(Assignment {
            var: WriteValue::Variable(variable_export.unwrap()),
            op: None,
            right: translate_export(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                expr,
            ),
        })),
        sleigh_rs::execution::Statement::CpuBranch(bra) => Some(Statement::CpuBranch(CpuBranch {
            cond: bra.cond.as_ref().map(|cond| {
                translate_expr(
                    sleigh_data,
                    addr,
                    instruction_match,
                    constructor_match,
                    table_variable_map,
                    var_offset,
                    cond,
                )
            }),
            call: bra.call,
            direct: bra.direct,
            dst: translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                &bra.dst,
            ),
        })),
        sleigh_rs::execution::Statement::LocalGoto(goto) => Some(Statement::LocalGoto(LocalGoto {
            dst: BlockId(goto.dst.0 + block_offset),
            cond: goto.cond.as_ref().map(|cond| {
                translate_expr(
                    sleigh_data,
                    addr,
                    instruction_match,
                    constructor_match,
                    table_variable_map,
                    var_offset,
                    cond,
                )
            }),
        })),
        sleigh_rs::execution::Statement::UserCall(fun) => Some(Statement::UserCall(UserCall {
            function: fun.function,
            params: fun
                .params
                .iter()
                .map(|p| {
                    translate_expr(
                        sleigh_data,
                        addr,
                        instruction_match,
                        constructor_match,
                        table_variable_map,
                        var_offset,
                        p,
                    )
                })
                .collect(),
        })),
        sleigh_rs::execution::Statement::Build(build) => {
            let build_match = constructor_match.sub_tables.get(&build.table.id).unwrap();
            let build_table = sleigh_data.table(build_match.table_id);
            let build_constructor = build_table.constructor(build_match.entry.constructor);
            let Some(build_execution) = &build_constructor.execution else {
                return Err(());
            };
            // if it exports something
            let variable_export = build_execution.export().next().map(|expr| {
                let var_id = VariableId(execution.variables.len());
                execution.variables.push(Variable {
                    name: format!("{}_export", build_table.name()),
                    len_bits: expr.len_bits(sleigh_data),
                });
                table_variable_map.insert(build.table.id, var_id);
                var_id
            });
            inline_constructor(
                sleigh_data,
                addr,
                instruction_match,
                build_match,
                execution,
                BlockId(block_id),
                variable_export,
                delay_slot,
            )?;
            None
        }
        sleigh_rs::execution::Statement::Declare(_) => None,
        sleigh_rs::execution::Statement::Assignment(ass) => Some(translate_write_value(
            sleigh_data,
            addr,
            instruction_match,
            constructor_match,
            table_variable_map,
            var_offset,
            ass,
        )),
        sleigh_rs::execution::Statement::MemWrite(write) => Some(Statement::MemWrite(MemWrite {
            mem: write.mem,
            addr: translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                &write.addr,
            ),
            right: translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                &write.right,
            ),
        })),
    })
}

fn translate_expr(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    table_variable_map: &mut HashMap<TableId, VariableId>,
    var_offset: usize,
    expr: &sleigh_rs::execution::Expr,
) -> Expr {
    match expr {
        sleigh_rs::execution::Expr::Value(value) => Expr::Value(translate_expr_element(
            sleigh_data,
            addr,
            instruction_match,
            constructor_match,
            table_variable_map,
            var_offset,
            value,
        )),
        // TODO if translate_expr returns value, evaluate that
        sleigh_rs::execution::Expr::Op(sleigh_rs::execution::ExprBinaryOp {
            location: _,
            len_bits,
            op,
            left,
            right,
        }) => Expr::Op(ExprBinaryOp {
            len_bits: *len_bits,
            op: *op,
            left: Box::new(translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                left,
            )),
            right: Box::new(translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                right,
            )),
        }),
    }
}

fn translate_expr_element(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    table_variable_map: &mut HashMap<TableId, VariableId>,
    var_offset: usize,
    expr: &sleigh_rs::execution::ExprElement,
) -> ExprElement {
    match expr {
        sleigh_rs::execution::ExprElement::Value(value) => {
            ExprElement::Value(translate_expr_value(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                value,
            ))
        }
        sleigh_rs::execution::ExprElement::UserCall(call) => ExprElement::UserCall(UserCall {
            function: call.function,
            params: call
                .params
                .iter()
                .map(|param| {
                    translate_expr(
                        sleigh_data,
                        addr,
                        instruction_match,
                        constructor_match,
                        table_variable_map,
                        var_offset,
                        param,
                    )
                })
                .collect(),
        }),
        sleigh_rs::execution::ExprElement::Reference(value) => ExprElement::Value(ExprValue::Int {
            len_bits: value.len_bits,
            number: Number::Positive(translate_reference(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                &value.value,
            )),
        }),
        // TODO if translate_expr returns value, evaluate that
        sleigh_rs::execution::ExprElement::Op(value) => ExprElement::Op(ExprUnaryOp {
            output_bits: value.output_bits,
            op: value.op.clone(),
            input: Box::new(translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                &value.input,
            )),
        }),
        sleigh_rs::execution::ExprElement::New(_) => unimplemented!(),
        sleigh_rs::execution::ExprElement::CPool(_) => unimplemented!(),
    }
}

fn translate_expr_value(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    table_variable_map: &mut HashMap<TableId, VariableId>,
    var_offset: usize,
    expr: &sleigh_rs::execution::ExprValue,
) -> ExprValue {
    match expr {
        sleigh_rs::execution::ExprValue::Int(x) => ExprValue::Int {
            len_bits: x.size,
            number: x.number,
        },
        sleigh_rs::execution::ExprValue::TokenField(x) => ExprValue::Int {
            len_bits: x.size,
            // TODO translate based on the meaning
            number: constructor_match
                .token_fields
                .get(&x.id)
                .unwrap()
                .clone()
                .try_into()
                .unwrap(),
        },
        sleigh_rs::execution::ExprValue::InstStart(_) => ExprValue::Int {
            len_bits: sleigh_data.addr_bytes(),
            number: Number::Positive(addr),
        },
        sleigh_rs::execution::ExprValue::InstNext(_) => ExprValue::Int {
            len_bits: sleigh_data.addr_bytes(),
            number: Number::Positive(
                addr + u64::try_from(instruction_match.constructor.len).unwrap(),
            ),
        },
        sleigh_rs::execution::ExprValue::Varnode(var) => ExprValue::Varnode(var.id),
        sleigh_rs::execution::ExprValue::Context(context) => ExprValue::Int {
            len_bits: context.size,
            // TODO translate based on the meaning
            number: super::get_context_field_value(
                sleigh_data,
                &instruction_match.context,
                context.id,
            )
            .clone()
            .try_into()
            .unwrap(),
        },
        sleigh_rs::execution::ExprValue::Bitrange(x) => ExprValue::Bitrange {
            len_bits: x.size,
            value: x.id,
        },
        sleigh_rs::execution::ExprValue::Table(x) => {
            ExprValue::ExeVar(*table_variable_map.get(&x.id).unwrap())
        }
        // TODO value from the final disassembled value or at the time of disassembly
        sleigh_rs::execution::ExprValue::DisVar(var) => ExprValue::Int {
            len_bits: var.size,
            number: constructor_match
                .disassembly_vars
                .get(&var.id)
                .unwrap()
                .clone()
                .try_into()
                .unwrap(),
        },
        sleigh_rs::execution::ExprValue::ExeVar(var) => {
            ExprValue::ExeVar(VariableId(var.id.0 + var_offset))
        }
    }
}

fn translate_reference(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    expr: &sleigh_rs::execution::ReferencedValue,
) -> u64 {
    match expr {
        sleigh_rs::execution::ReferencedValue::TokenField(
            sleigh_rs::execution::RefTokenField { location: _, id },
        ) => {
            let token = sleigh_data.token_field(*id);
            let token_value = constructor_match.token_fields.get(id).unwrap();
            let sleigh_rs::meaning::Meaning::Varnode(varnodes_id) = token.meaning() else {
                panic!();
            };
            let varnodes = sleigh_data.attach_varnode(varnodes_id);
            let varnode_id = varnodes
                .0
                .iter()
                .find_map(|(value, id)| {
                    (i128::try_from(*value).unwrap() == *token_value).then_some(id)
                })
                .unwrap();
            let varnode = sleigh_data.varnode(*varnode_id);
            varnode.address
        }
        sleigh_rs::execution::ReferencedValue::InstStart(_) => addr,
        sleigh_rs::execution::ReferencedValue::InstNext(_) => {
            addr + u64::try_from(instruction_match.constructor.len).unwrap()
        }
        sleigh_rs::execution::ReferencedValue::Table(_) => todo!(),
    }
}

fn translate_export(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    table_variable_map: &mut HashMap<TableId, VariableId>,
    var_offset: usize,
    expr: &sleigh_rs::execution::Export,
) -> Expr {
    match expr {
        sleigh_rs::execution::Export::Const {
            len_bits,
            location: _,
            export,
        } => match export {
            sleigh_rs::execution::ExportConst::DisVar(dis_id) => {
                Expr::Value(ExprElement::Value(ExprValue::Int {
                    len_bits: *len_bits,
                    number: constructor_match
                        .disassembly_vars
                        .get(dis_id)
                        .unwrap()
                        .clone()
                        .try_into()
                        .unwrap(),
                }))
            }
            sleigh_rs::execution::ExportConst::TokenField(id) => {
                // TODO translate based on the meaning
                Expr::Value(ExprElement::Value(ExprValue::Int {
                    len_bits: *len_bits,
                    number: constructor_match
                        .token_fields
                        .get(id)
                        .unwrap()
                        .clone()
                        .try_into()
                        .unwrap(),
                }))
            }
            sleigh_rs::execution::ExportConst::Context(context_id) => {
                // TODO translate based on the meaning
                Expr::Value(ExprElement::Value(ExprValue::Int {
                    len_bits: *len_bits,
                    number: super::get_context_field_value(
                        sleigh_data,
                        &instruction_match.context,
                        *context_id,
                    )
                    .clone()
                    .try_into()
                    .unwrap(),
                }))
            }
            sleigh_rs::execution::ExportConst::InstructionStart => {
                Expr::Value(ExprElement::Value(ExprValue::Int {
                    len_bits: *len_bits,
                    number: addr.into(),
                }))
            }
            sleigh_rs::execution::ExportConst::ExeVar(var) => Expr::Value(ExprElement::Value(
                ExprValue::ExeVar(VariableId(var.0 + var_offset)),
            )),
            sleigh_rs::execution::ExportConst::Table(_) => todo!(),
        },
        sleigh_rs::execution::Export::Value(val) => translate_expr(
            sleigh_data,
            addr,
            instruction_match,
            constructor_match,
            table_variable_map,
            var_offset,
            val,
        ),
        sleigh_rs::execution::Export::Reference {
            addr: addr_mem,
            memory,
        } => Expr::Value(ExprElement::Op(ExprUnaryOp {
            output_bits: memory.len_bytes,
            op: Unary::Dereference(MemoryLocation {
                space: memory.space,
                len_bytes: memory.len_bytes,
            }),
            input: Box::new(translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                addr_mem,
            )),
        })),
    }
}

fn translate_write_value(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
    constructor_match: &ConstructorMatch,
    table_variable_map: &mut HashMap<TableId, VariableId>,
    var_offset: usize,
    ass: &sleigh_rs::execution::Assignment,
) -> Statement {
    match &ass.var {
        sleigh_rs::execution::WriteValue::Varnode(varnode) => Statement::Assignment(Assignment {
            var: WriteValue::Varnode(varnode.id),
            op: ass.op.clone(),
            right: translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                &ass.right,
            ),
        }),
        sleigh_rs::execution::WriteValue::Bitrange(bitrange) => Statement::Assignment(Assignment {
            var: WriteValue::Bitrange(bitrange.id),
            op: ass.op.clone(),
            right: translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                &ass.right,
            ),
        }),
        sleigh_rs::execution::WriteValue::TokenField(_) => todo!(),
        sleigh_rs::execution::WriteValue::TableExport(_) => todo!(),
        sleigh_rs::execution::WriteValue::Local(id) => Statement::Assignment(Assignment {
            var: WriteValue::Variable(VariableId(id.id.0 + var_offset)),
            op: ass.op.clone(),
            right: translate_expr(
                sleigh_data,
                addr,
                instruction_match,
                constructor_match,
                table_variable_map,
                var_offset,
                &ass.right,
            ),
        }),
    }
}
