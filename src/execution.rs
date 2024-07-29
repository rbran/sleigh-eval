use std::collections::HashMap;

use sleigh_rs::execution::{AssignmentOp, Binary, BranchCall, MemoryLocation, Unary};
use sleigh_rs::{
    BitrangeId, Number, NumberNonZeroUnsigned, NumberUnsigned, Sleigh, TableId, UserFunctionId,
    VarnodeId,
};
use tracing::warn;

use crate::{ConstructorMatch, InstructionMatch};

#[derive(Clone, Debug)]
pub struct Execution {
    // NOTE: delay slot should be only set once, we will allow delay slot 0 for now
    pub delay_slot: Option<NumberUnsigned>,
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
    Memory { memory: MemoryLocation, addr: Expr },
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
    pub fn len_bits(&self, sleigh: &Sleigh, execution: &Execution) -> NumberNonZeroUnsigned {
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

#[derive(Clone, Copy, Debug)]
enum TableExport {
    Int {
        len_bits: NumberNonZeroUnsigned,
        value: Number,
    },
    Varnode(VarnodeId),
    Variable(VariableId),
    MemoryReference {
        addr: TranslatedVariable,
        mem: MemoryLocation,
    },
}

#[derive(Clone, Copy, Debug)]
enum TranslatedVariable {
    Variable(VariableId),
    Int {
        len_bits: NumberNonZeroUnsigned,
        value: Number,
    },
}
impl TranslatedVariable {
    fn to_expr(self) -> Expr {
        match self {
            TranslatedVariable::Variable(var) => {
                Expr::Value(ExprElement::Value(ExprValue::ExeVar(var)))
            }
            TranslatedVariable::Int { value, len_bits } => {
                Expr::Value(ExprElement::Value(ExprValue::Int {
                    len_bits,
                    number: value,
                }))
            }
        }
    }
}

struct ExecutionBuilder<'a> {
    sleigh_data: &'a Sleigh,
    addr: u64,
    execution: Execution,
    instruction_match: &'a InstructionMatch,
}

struct ExecutionConstructorInliner<'a, 'b> {
    builder: &'b mut ExecutionBuilder<'a>,
    sleigh_execution: &'a sleigh_rs::execution::Execution,
    constructor_match: &'a ConstructorMatch,
    // current block on the execution builder
    current_block: BlockId,
    variables_map: HashMap<sleigh_rs::execution::VariableId, TranslatedVariable>,
    table_variable_map: HashMap<TableId, TableExport>,
    // block offset to translate sleigh_rs blocks to execution builder blocks
    block_offset: usize,
    // the value this constructor exports
    constructor_export: Option<TableExport>,
}

impl<'a, 'b> core::ops::Deref for ExecutionConstructorInliner<'a, '_> {
    type Target = ExecutionBuilder<'a>;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}
impl<'a> core::ops::DerefMut for ExecutionConstructorInliner<'a, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.builder
    }
}

impl<'a> ExecutionBuilder<'a> {
    fn new(sleigh_data: &'a Sleigh, instruction_match: &'a InstructionMatch, addr: u64) -> Self {
        Self {
            sleigh_data,
            addr,
            instruction_match,
            execution: Execution {
                delay_slot: None,
                variables: vec![],
                // create the entry block, populated later by inline_constructor
                blocks: vec![Block {
                    name: None,
                    next: None,
                    statements: vec![],
                }],
            },
        }
    }

    fn finish(self) -> Execution {
        self.execution
    }

    fn inline_constructor(
        &mut self,
        constructor_match: &'a ConstructorMatch,
        current_block: BlockId,
    ) -> Result<Option<TableExport>, ()> {
        // the offset of blocks: `block_id = sleigh_block_id + block_offset`
        let block_offset = self.execution.blocks.len();

        // if it exports something
        let build_table = self.sleigh_data.table(constructor_match.table_id);
        let build_constructor = build_table.constructor(constructor_match.entry.constructor);
        let Some(sleigh_execution) = &build_constructor.execution else {
            // if one table is not implemented, we can't solve this
            warn!("Table `{}` is not implemented", build_table.name());
            return Err(());
        };

        let exported = (ExecutionConstructorInliner {
            builder: self,
            sleigh_execution,
            constructor_match,
            current_block,
            variables_map: HashMap::default(),
            table_variable_map: HashMap::default(),
            block_offset,
            // will be populated by the export statement translation
            constructor_export: None,
        })
        .finish()?;
        Ok(exported)
    }

    fn create_variable(&mut self, variable: Variable) -> VariableId {
        let id = self.execution.variables.len();
        self.execution.variables.push(variable);
        VariableId(id)
    }
}

pub fn to_execution_instruction(
    sleigh_data: &Sleigh,
    addr: u64,
    instruction_match: &InstructionMatch,
) -> Option<Execution> {
    let mut builder = ExecutionBuilder::new(sleigh_data, instruction_match, addr);

    let constructor_match = &instruction_match.constructor;
    let table = sleigh_data.table(constructor_match.table_id);
    let instruction = table.constructor(constructor_match.entry.constructor);
    let Some(execution) = &instruction.execution else {
        let mneumonic = instruction
            .display
            .mneumonic
            .as_ref()
            .map(String::as_str)
            .unwrap_or_else(|| "PSEUDO");
        warn!(
            "Instruction `{}` at `{}` is not implemented",
            mneumonic, &instruction.location
        );
        return None;
    };
    assert!(!execution.blocks().is_empty());

    let exported = builder
        .inline_constructor(constructor_match, BlockId(0))
        .ok()?;
    // instruction table can't export values
    assert!(exported.is_none());

    Some(builder.finish())
}

impl<'a, 'b> ExecutionConstructorInliner<'a, 'b> {
    fn map_variable(&mut self, old: sleigh_rs::execution::VariableId, value: TranslatedVariable) {
        self.variables_map
            .insert(old, value)
            .map(|_| panic!("Variable mapped multiple times"))
            .unwrap_or(());
    }

    fn replace_variable(
        &mut self,
        old: sleigh_rs::execution::VariableId,
        value: TranslatedVariable,
    ) {
        self.variables_map.insert(old, value);
    }

    fn variable(&self, variable_id: VariableId) -> &Variable {
        &self.builder.execution.variables[variable_id.0]
    }

    fn sleigh_variable_value(
        &self,
        variable_id: sleigh_rs::execution::VariableId,
    ) -> Option<TranslatedVariable> {
        self.variables_map.get(&variable_id).copied()
    }

    fn map_table(&mut self, table: TableId, value: TableExport) {
        self.table_variable_map
            .insert(table, value)
            .map(|_| panic!("Table export mapped multiple times"))
            .unwrap_or(());
    }

    fn table(&self, table: TableId) -> Option<TableExport> {
        self.table_variable_map.get(&table).copied()
    }

    fn finish(mut self) -> Result<Option<TableExport>, ()> {
        // create empty blocks, excluding the entry one, the entry block is the block
        // this constructor is being build at
        let first_block = self.sleigh_execution.blocks().first().unwrap();
        let old_next_block = self.execution.blocks[self.current_block.0]
            .next
            .map(|block| BlockId(block.0 + self.block_offset));
        let current_block_idx = self.current_block.0;
        self.execution.blocks[current_block_idx].next = first_block
            .next
            .map(|block_id| BlockId(block_id.0 + self.block_offset));
        for block in self.sleigh_execution.blocks().iter().skip(1) {
            let new_block = Block {
                name: block.name.as_ref().map(|name| name.clone()),
                next: block
                    .next
                    .map(|block_id| BlockId(block_id.0 + self.block_offset))
                    .or(old_next_block),
                statements: vec![],
            };
            self.execution.blocks.push(new_block);
        }

        // TODO - in sleigh_rs all tables should have build statements
        // build all tables without build statements
        for (subtable_id, build_match) in self.constructor_match.sub_tables.iter() {
            // ignore if the table will be build by an build statement
            let sub_table_build_is_explicit = self.sleigh_execution
                .blocks()
                .iter()
                .flat_map(|b| b.statements.iter())
                .any(|s| matches!(s, sleigh_rs::execution::Statement::Build(build) if build.table.id == *subtable_id));
            if sub_table_build_is_explicit {
                continue;
            }

            let current_block = self.current_block;
            let exported = self.inline_constructor(build_match, current_block)?;
            if let Some(exported) = exported {
                self.map_table(*subtable_id, exported);
            }
        }

        // translate all the statements, populating the empty blocks created previously
        let blocks_id = [self.current_block.0]
            .into_iter()
            .chain(self.block_offset..);
        let blocks = self.sleigh_execution.blocks().iter().zip(blocks_id);
        for (sleigh_block, block_id) in blocks {
            for statement in &sleigh_block.statements {
                self.translate_statement(block_id, statement)?;
            }
        }

        Ok(self.constructor_export)
    }

    fn insert_statement(&mut self, block_id: usize, statement: Statement) {
        self.execution.blocks[block_id].statements.push(statement);
    }

    fn translate_statement(
        &mut self,
        block_id: usize,
        statement: &sleigh_rs::execution::Statement,
    ) -> Result<(), ()> {
        match statement {
            sleigh_rs::execution::Statement::Delayslot(x) => {
                self.execution
                    .delay_slot
                    .replace(*x)
                    .map(|_| panic!("multiple delay slot"));
            }
            sleigh_rs::execution::Statement::Export(expr) => {
                self.translate_export(block_id, expr)?;
            }
            sleigh_rs::execution::Statement::CpuBranch(bra) => {
                let statement = Statement::CpuBranch(CpuBranch {
                    cond: bra.cond.as_ref().map(|cond| self.translate_expr(cond)),
                    call: bra.call,
                    direct: bra.direct,
                    dst: self.translate_expr(&bra.dst),
                });
                self.insert_statement(block_id, statement);
            }
            sleigh_rs::execution::Statement::LocalGoto(goto) => {
                let statement = Statement::LocalGoto(LocalGoto {
                    dst: BlockId(goto.dst.0 + self.block_offset),
                    cond: goto.cond.as_ref().map(|cond| self.translate_expr(cond)),
                });
                self.insert_statement(block_id, statement);
            }
            sleigh_rs::execution::Statement::UserCall(fun) => {
                let statement = Statement::UserCall(UserCall {
                    function: fun.function,
                    params: fun.params.iter().map(|p| self.translate_expr(p)).collect(),
                });
                self.insert_statement(block_id, statement);
            }
            sleigh_rs::execution::Statement::Build(build) => {
                let build_match = self
                    .constructor_match
                    .sub_tables
                    .get(&build.table.id)
                    .unwrap();
                let exported = self.inline_constructor(build_match, BlockId(block_id))?;
                if let Some(exported) = exported {
                    self.map_table(build.table.id, exported);
                }
            }
            sleigh_rs::execution::Statement::Assignment(ass) => {
                self.translate_assignment(block_id, ass)?;
            }
            sleigh_rs::execution::Statement::MemWrite(write) => {
                let statement = Statement::Assignment(Assignment {
                    op: None,
                    var: WriteValue::Memory {
                        memory: write.mem,
                        addr: self.translate_expr(&write.addr),
                    },
                    right: self.translate_expr(&write.right),
                });
                self.insert_statement(block_id, statement);
            }
            // variables are create on use, so the value can be solved
            sleigh_rs::execution::Statement::Declare(_) => {}
        }
        Ok(())
    }

    fn translate_expr(&self, expr: &sleigh_rs::execution::Expr) -> Expr {
        match expr {
            sleigh_rs::execution::Expr::Value(value) => {
                Expr::Value(self.translate_expr_element(value))
            }
            sleigh_rs::execution::Expr::Op(sleigh_rs::execution::ExprBinaryOp {
                location: _,
                len_bits,
                op,
                left,
                right,
            }) => {
                let left = self.translate_expr(left);
                let right = self.translate_expr(right);
                // if translate_expr returns value, evaluate that
                if let (
                    Expr::Value(ExprElement::Value(ExprValue::Int {
                        len_bits: len_left,
                        number: value_left,
                    })),
                    Expr::Value(ExprElement::Value(ExprValue::Int {
                        len_bits: len_right,
                        number: value_right,
                    })),
                ) = (&left, &right)
                {
                    let result = eval_execution_binary_op(
                        *value_left,
                        *len_left,
                        *op,
                        *value_right,
                        *len_right,
                        *len_bits,
                    );
                    if let Some(result) = result {
                        return Expr::Value(ExprElement::Value(ExprValue::Int {
                            len_bits: *len_bits,
                            number: result,
                        }));
                    }
                }
                Expr::Op(ExprBinaryOp {
                    len_bits: *len_bits,
                    op: *op,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
        }
    }

    fn translate_expr_element(&self, expr: &sleigh_rs::execution::ExprElement) -> ExprElement {
        match expr {
            sleigh_rs::execution::ExprElement::Value(value) => self.translate_expr_value(value),
            sleigh_rs::execution::ExprElement::UserCall(call) => ExprElement::UserCall(UserCall {
                function: call.function,
                params: call
                    .params
                    .iter()
                    .map(|param| self.translate_expr(param))
                    .collect(),
            }),
            sleigh_rs::execution::ExprElement::Reference(value) => {
                ExprElement::Value(ExprValue::Int {
                    len_bits: value.len_bits,
                    number: Number::Positive(self.translate_reference(&value.value)),
                })
            }
            // TODO if translate_expr returns value, evaluate that
            sleigh_rs::execution::ExprElement::Op(value) => ExprElement::Op(ExprUnaryOp {
                output_bits: value.output_bits,
                op: value.op.clone(),
                input: Box::new(self.translate_expr(&value.input)),
            }),
            sleigh_rs::execution::ExprElement::New(_) => unimplemented!(),
            sleigh_rs::execution::ExprElement::CPool(_) => unimplemented!(),
        }
    }

    fn translate_expr_value(&self, expr: &sleigh_rs::execution::ExprValue) -> ExprElement {
        match expr {
            sleigh_rs::execution::ExprValue::Int(x) => ExprElement::Value(ExprValue::Int {
                len_bits: x.size,
                number: x.number,
            }),
            sleigh_rs::execution::ExprValue::TokenField(x) => {
                let tf = self.sleigh_data.token_field(x.id);
                let tf_value = self.constructor_match.token_fields.get(&x.id).unwrap();
                match tf.meaning() {
                    sleigh_rs::meaning::Meaning::Varnode(id) => {
                        let attach = self.sleigh_data.attach_varnode(id);
                        let varnode_id = attach
                            .find_value(usize::try_from(*tf_value).unwrap())
                            .unwrap();
                        ExprElement::Value(ExprValue::Varnode(varnode_id))
                    }
                    sleigh_rs::meaning::Meaning::Number(_, id) => {
                        let attach = self.sleigh_data.attach_number(id);
                        let number = attach
                            .find_value(usize::try_from(*tf_value).unwrap())
                            .unwrap();
                        ExprElement::Value(ExprValue::Int {
                            len_bits: expr.len_bits(self.sleigh_data, self.sleigh_execution),
                            number,
                        })
                    }
                    sleigh_rs::meaning::Meaning::Literal(_)
                    | sleigh_rs::meaning::Meaning::NoAttach(_) => {
                        ExprElement::Value(ExprValue::Int {
                            len_bits: x.size,
                            // TODO translate based on the meaning
                            number: tf_value.clone().try_into().unwrap(),
                        })
                    }
                }
            }
            sleigh_rs::execution::ExprValue::InstStart(_) => ExprElement::Value(ExprValue::Int {
                len_bits: self.sleigh_data.addr_bytes(),
                number: Number::Positive(self.addr),
            }),
            sleigh_rs::execution::ExprValue::InstNext(_) => ExprElement::Value(ExprValue::Int {
                len_bits: self.sleigh_data.addr_bytes(),
                number: Number::Positive(
                    self.addr + u64::try_from(self.instruction_match.constructor.len).unwrap(),
                ),
            }),
            sleigh_rs::execution::ExprValue::Varnode(var) => {
                ExprElement::Value(ExprValue::Varnode(var.id))
            }
            sleigh_rs::execution::ExprValue::Context(context) => {
                let context_sleigh = self.sleigh_data.context(context.id);
                let context_value = super::get_context_field_value(
                    self.sleigh_data,
                    &self.instruction_match.context,
                    context.id,
                );
                match context_sleigh.meaning() {
                    sleigh_rs::meaning::Meaning::Varnode(id) => {
                        let attach = self.sleigh_data.attach_varnode(id);
                        let varnode_id = attach
                            .find_value(usize::try_from(context_value).unwrap())
                            .unwrap();
                        ExprElement::Value(ExprValue::Varnode(varnode_id))
                    }
                    sleigh_rs::meaning::Meaning::Number(_, id) => {
                        let attach = self.sleigh_data.attach_number(id);
                        let number = attach
                            .find_value(usize::try_from(context_value).unwrap())
                            .unwrap();
                        ExprElement::Value(ExprValue::Int {
                            len_bits: expr.len_bits(self.sleigh_data, self.sleigh_execution),
                            number,
                        })
                    }
                    sleigh_rs::meaning::Meaning::Literal(_)
                    | sleigh_rs::meaning::Meaning::NoAttach(_) => {
                        ExprElement::Value(ExprValue::Int {
                            len_bits: context.size,
                            // TODO translate based on the meaning
                            number: context_value.try_into().unwrap(),
                        })
                    }
                }
            }
            sleigh_rs::execution::ExprValue::Bitrange(x) => {
                ExprElement::Value(ExprValue::Bitrange {
                    len_bits: x.size,
                    value: x.id,
                })
            }
            sleigh_rs::execution::ExprValue::Table(x) => {
                let table_export = self.table_variable_map.get(&x.id).unwrap();
                match table_export {
                    TableExport::Int { len_bits, value } => ExprElement::Value(ExprValue::Int {
                        len_bits: *len_bits,
                        number: *value,
                    }),
                    TableExport::Varnode(varnode_id) => {
                        ExprElement::Value(ExprValue::Varnode(*varnode_id))
                    }
                    TableExport::Variable(variable_id) => {
                        ExprElement::Value(ExprValue::ExeVar(*variable_id))
                    }
                    TableExport::MemoryReference { addr, mem } => {
                        let addr = match addr {
                            TranslatedVariable::Variable(var) => ExprValue::ExeVar(*var),
                            TranslatedVariable::Int { value, len_bits } => ExprValue::Int {
                                len_bits: *len_bits,
                                number: *value,
                            },
                        };
                        ExprElement::Op(ExprUnaryOp {
                            output_bits: mem.len_bytes,
                            op: Unary::Dereference(*mem),
                            input: Box::new(Expr::Value(ExprElement::Value(addr))),
                        })
                    }
                }
            }
            // TODO value from the final disassembled value or at the time of disassembly
            sleigh_rs::execution::ExprValue::DisVar(var) => ExprElement::Value(ExprValue::Int {
                len_bits: var.size,
                number: self
                    .constructor_match
                    .disassembly_vars
                    .get(&var.id)
                    .unwrap()
                    .clone()
                    .try_into()
                    .unwrap(),
            }),
            sleigh_rs::execution::ExprValue::ExeVar(old_var) => {
                let variable = self.sleigh_variable_value(old_var.id).unwrap();
                match variable {
                    TranslatedVariable::Variable(variable_id) => {
                        ExprElement::Value(ExprValue::ExeVar(variable_id))
                    }
                    TranslatedVariable::Int { len_bits, value } => {
                        ExprElement::Value(ExprValue::Int {
                            len_bits,
                            number: value,
                        })
                    }
                }
            }
        }
    }

    fn translate_reference(&self, expr: &sleigh_rs::execution::ReferencedValue) -> u64 {
        match expr {
            sleigh_rs::execution::ReferencedValue::TokenField(
                sleigh_rs::execution::RefTokenField { location: _, id },
            ) => {
                let token = self.sleigh_data.token_field(*id);
                let token_value = self.constructor_match.token_fields.get(id).unwrap();
                let sleigh_rs::meaning::Meaning::Varnode(varnodes_id) = token.meaning() else {
                    panic!();
                };
                let varnodes = self.sleigh_data.attach_varnode(varnodes_id);
                let varnode_id = varnodes
                    .0
                    .iter()
                    .find_map(|(value, id)| {
                        (i128::try_from(*value).unwrap() == *token_value).then_some(id)
                    })
                    .unwrap();
                let varnode = self.sleigh_data.varnode(*varnode_id);
                varnode.address
            }
            sleigh_rs::execution::ReferencedValue::InstStart(_) => self.addr,
            sleigh_rs::execution::ReferencedValue::InstNext(_) => {
                self.addr + u64::try_from(self.instruction_match.constructor.len).unwrap()
            }
            sleigh_rs::execution::ReferencedValue::Table(_) => todo!(),
        }
    }

    fn translate_export(
        &mut self,
        block_id: usize,
        expr: &sleigh_rs::execution::Export,
    ) -> Result<(), ()> {
        let table_id = self.constructor_match.table_id;
        let table = self.sleigh_data.table(table_id);
        let exported = match expr {
            // TODO handle multiple possible return blocks
            sleigh_rs::execution::Export::Const {
                len_bits: _,
                location: _,
                export,
            } => self.translate_export_const(export),
            sleigh_rs::execution::Export::Value(val) => {
                match self.translate_expr(val) {
                    // if the exported value is solved, just set the solved value for the table
                    Expr::Value(ExprElement::Value(ExprValue::Int { len_bits, number })) => {
                        TableExport::Int {
                            len_bits,
                            value: number,
                        }
                    }
                    // if variable, just solve the table to that variable
                    Expr::Value(ExprElement::Value(ExprValue::ExeVar(var))) => {
                        TableExport::Variable(var)
                    }
                    // if varnode, then we export a reference
                    Expr::Value(ExprElement::Value(ExprValue::Varnode(varnode))) => {
                        TableExport::Varnode(varnode)
                    }
                    Expr::Value(ExprElement::Value(ExprValue::Bitrange { .. })) => todo!(),

                    // if a complex Expr, create a variable and assign to it
                    expr @ Expr::Op(_)
                    | expr @ Expr::Value(ExprElement::Op(_) | ExprElement::UserCall(_)) => {
                        let variable = Variable {
                            name: format!("{}_export", table.name()),
                            len_bits: table.export.unwrap().len(),
                        };
                        let export_variable = self.builder.create_variable(variable);
                        let assignment = Statement::Assignment(Assignment {
                            var: WriteValue::Variable(export_variable),
                            op: None,
                            right: expr,
                        });
                        self.insert_statement(block_id, assignment);
                        TableExport::Variable(export_variable)
                    }
                }
            }
            // associate the table export with a memory reference
            sleigh_rs::execution::Export::Reference {
                addr: addr_mem,
                memory,
            } => {
                let addr_mem = self.translate_expr(addr_mem);
                // if the address is not static is create a variable to store it
                let addr =
                    if let Expr::Value(ExprElement::Value(ExprValue::Int { len_bits, number })) =
                        &addr_mem
                    {
                        TranslatedVariable::Int {
                            len_bits: *len_bits,
                            value: *number,
                        }
                    } else {
                        let variable = Variable {
                            name: format!("{}_export", table.name()),
                            len_bits: table.export.unwrap().len(),
                        };
                        let export_variable = self.builder.create_variable(variable);
                        let statement = Statement::Assignment(Assignment {
                            var: WriteValue::Variable(export_variable),
                            op: None,
                            right: addr_mem,
                        });
                        self.insert_statement(block_id, statement);
                        TranslatedVariable::Variable(export_variable)
                    };
                TableExport::MemoryReference { addr, mem: *memory }
            }
        };
        self.constructor_export = Some(exported);
        Ok(())
    }

    fn translate_export_const(&self, export: &sleigh_rs::execution::ExportConst) -> TableExport {
        let len_bits = self.sleigh_execution.export_len().map(|exp| exp.len());
        match export {
            sleigh_rs::execution::ExportConst::DisVar(dis_id) => TableExport::Int {
                value: self
                    .constructor_match
                    .disassembly_vars
                    .get(dis_id)
                    .unwrap()
                    .clone()
                    .try_into()
                    .unwrap(),
                len_bits: len_bits.unwrap(),
            },
            sleigh_rs::execution::ExportConst::TokenField(id) => {
                // TODO translate based on the meaning
                TableExport::Int {
                    value: self
                        .constructor_match
                        .token_fields
                        .get(id)
                        .unwrap()
                        .clone()
                        .try_into()
                        .unwrap(),
                    len_bits: len_bits.unwrap(),
                }
            }
            sleigh_rs::execution::ExportConst::Context(context_id) => {
                // TODO translate based on the meaning
                TableExport::Int {
                    value: super::get_context_field_value(
                        self.sleigh_data,
                        &self.instruction_match.context,
                        *context_id,
                    )
                    .clone()
                    .try_into()
                    .unwrap(),
                    len_bits: len_bits.unwrap(),
                }
            }
            sleigh_rs::execution::ExportConst::InstructionStart => TableExport::Int {
                value: self.addr.into(),
                len_bits: len_bits.unwrap(),
            },
            sleigh_rs::execution::ExportConst::ExeVar(var) => {
                match self.sleigh_variable_value(*var).unwrap() {
                    TranslatedVariable::Variable(var) => TableExport::Variable(var),
                    TranslatedVariable::Int { len_bits, value } => {
                        TableExport::Int { len_bits, value }
                    }
                }
            }
            sleigh_rs::execution::ExportConst::Table(table_id) => self.table(*table_id).unwrap(),
        }
    }

    fn translate_assignment(
        &mut self,
        block_id: usize,
        ass: &sleigh_rs::execution::Assignment,
    ) -> Result<(), ()> {
        let right = self.translate_expr(&ass.right);
        match &ass.var {
            sleigh_rs::execution::WriteValue::Varnode(varnode) => {
                let statement = Statement::Assignment(Assignment {
                    var: WriteValue::Varnode(varnode.id),
                    op: ass.op.clone(),
                    right,
                });
                self.insert_statement(block_id, statement);
            }
            sleigh_rs::execution::WriteValue::Bitrange(bitrange) => {
                let statement = Statement::Assignment(Assignment {
                    var: WriteValue::Bitrange(bitrange.id),
                    op: ass.op.clone(),
                    right,
                });
                self.insert_statement(block_id, statement);
            }
            sleigh_rs::execution::WriteValue::Local(variable) => {
                self.translate_assignment_variable(block_id, ass.op.clone(), variable, right)?;
            }
            // all token fields can be translated into values
            sleigh_rs::execution::WriteValue::TokenField(tf_expr) => {
                let tf = self.sleigh_data.token_field(tf_expr.id);
                let tf_value = self
                    .constructor_match
                    .token_fields
                    .get(&tf_expr.id)
                    .unwrap();
                let sleigh_rs::meaning::Meaning::Varnode(varnodes_id) = tf.meaning() else {
                    panic!("Can't write to a token_field")
                };
                let tf_value =
                    usize::try_from(*tf_value).expect("Invalid value for TokenField meaning");
                let varnode_id = self
                    .sleigh_data
                    .attach_varnode(varnodes_id)
                    .0
                    .iter()
                    .find_map(|(value, varnode_id)| (*value == tf_value).then_some(varnode_id))
                    .expect("Unable to find TokenField Meaning");
                let statement = Statement::Assignment(Assignment {
                    var: WriteValue::Varnode(*varnode_id),
                    op: ass.op.clone(),
                    right,
                });
                self.insert_statement(block_id, statement);
            }
            sleigh_rs::execution::WriteValue::TableExport(write_table) => {
                let table_export = self.table(write_table.id).unwrap();
                let var = match table_export {
                    TableExport::Varnode(varnode) => WriteValue::Varnode(varnode),
                    TableExport::Variable(variable_id) => WriteValue::Variable(variable_id),
                    TableExport::MemoryReference { addr, mem } => WriteValue::Memory {
                        memory: mem,
                        addr: addr.to_expr(),
                    },
                    // TODO - is this what the original sleigh does?
                    // HACK - Tmp solution: if writing to a value, get the memory that other constructor
                    // export
                    TableExport::Int { len_bits, value } => {
                        let sleigh_table = self.sleigh_data.table(write_table.id);
                        let space_id =
                            find_table_export_reference(&self.sleigh_data, sleigh_table).unwrap();
                        match self.sleigh_data.space(space_id).space_type {
                            sleigh_rs::space::SpaceType::Rom => panic!("Can't write to ROM"),
                            sleigh_rs::space::SpaceType::Ram => {
                                assert!(len_bits.get() % 8 == 0);
                                let len_bytes = len_bits.get() / 8;
                                WriteValue::Memory {
                                    memory: MemoryLocation {
                                        space: space_id,
                                        len_bytes: len_bytes.try_into().unwrap(),
                                    },
                                    addr: Expr::Value(ExprElement::Value(ExprValue::Int {
                                        len_bits,
                                        number: value,
                                    })),
                                }
                            }
                            sleigh_rs::space::SpaceType::Register => {
                                // TODO traslate into bitrange?
                                assert!(len_bits.get() % 8 == 0);
                                let len_bytes = (len_bits.get() / 8).try_into().unwrap();
                                if let Ok(varnode_id) = try_find_varnode_at(
                                    self.sleigh_data,
                                    value.as_unsigned().unwrap(),
                                    len_bytes,
                                ) {
                                    WriteValue::Varnode(varnode_id)
                                } else {
                                    WriteValue::Memory {
                                        memory: MemoryLocation {
                                            space: space_id,
                                            len_bytes: len_bytes.try_into().unwrap(),
                                        },
                                        addr: Expr::Value(ExprElement::Value(ExprValue::Int {
                                            len_bits,
                                            number: value,
                                        })),
                                    }
                                }
                            }
                        }
                    }
                };
                let op = ass.op.clone();
                let statement = Statement::Assignment(Assignment { var, op, right });
                self.insert_statement(block_id, statement);
            }
        }
        Ok(())
    }

    fn translate_assignment_variable(
        &mut self,
        block_id: usize,
        op: Option<AssignmentOp>,
        variable: &sleigh_rs::execution::WriteExeVar,
        value: Expr,
    ) -> Result<(), ()> {
        enum ValueType {
            Int {
                value: Number,
                len_bits: NumberNonZeroUnsigned,
            },
            Variable(VariableId),
            Complex(Expr),
        }
        // TODO handle op is not None for all cases
        let value = match value {
            // if the value is just a number, then we just replace the variable with that number
            Expr::Value(ExprElement::Value(ExprValue::Int { len_bits, number })) => {
                ValueType::Int {
                    value: number,
                    len_bits,
                }
            }
            // if the variable is just an alias to other variable
            Expr::Value(ExprElement::Value(ExprValue::ExeVar(variable))) => {
                ValueType::Variable(variable)
            }
            // other more complex expression
            expr => ValueType::Complex(expr),
        };
        let sleigh_variable_id = variable.id;
        let left = self.sleigh_variable_value(sleigh_variable_id);
        match (left, value) {
            // variable don't exist, and can be aliased
            (None, ValueType::Int { value, len_bits }) => self.map_variable(
                sleigh_variable_id,
                TranslatedVariable::Int { value, len_bits },
            ),
            (None, ValueType::Variable(variable)) => {
                self.map_variable(sleigh_variable_id, TranslatedVariable::Variable(variable))
            }
            // TODO: how to handle that in multiple blocks?
            // variable exist, but the value changed from this point forward
            (Some(TranslatedVariable::Int { .. }), ValueType::Int { value, len_bits })
            | (Some(TranslatedVariable::Variable(_)), ValueType::Int { value, len_bits }) => self
                .replace_variable(
                    sleigh_variable_id,
                    TranslatedVariable::Int { value, len_bits },
                ),
            (Some(TranslatedVariable::Int { .. }), ValueType::Variable(variable))
            | (Some(TranslatedVariable::Variable(_)), ValueType::Variable(variable)) => {
                self.replace_variable(sleigh_variable_id, TranslatedVariable::Variable(variable))
            }
            // variable don't exist and assign a complex value to it, create a variable
            // and assign a value to it
            (Some(TranslatedVariable::Int { .. }), ValueType::Complex(complex))
            | (None, ValueType::Complex(complex)) => {
                let sleigh_variable = self.sleigh_execution.variable(sleigh_variable_id);
                let variable_id = self.create_variable(variable_from_sleigh(sleigh_variable));
                let statement = Statement::Assignment(Assignment {
                    var: WriteValue::Variable(variable_id),
                    op,
                    right: complex,
                });
                self.insert_statement(block_id, statement);
                self.replace_variable(
                    sleigh_variable_id,
                    TranslatedVariable::Variable(variable_id),
                );
            }
            // variable exists, assign a value to it
            (Some(TranslatedVariable::Variable(variable_id)), ValueType::Complex(complex)) => {
                let statement = Statement::Assignment(Assignment {
                    var: WriteValue::Variable(variable_id),
                    op,
                    right: complex,
                });
                self.insert_statement(block_id, statement);
            }
        }
        Ok(())
    }
}

fn eval_execution_binary_op(
    value_left: Number,
    len_left: NumberNonZeroUnsigned,
    op: Binary,
    value_right: Number,
    _len_right: NumberNonZeroUnsigned,
    _len_bits: NumberNonZeroUnsigned,
) -> Option<Number> {
    let result = match op {
        Binary::Mult => {
            value_left.as_unsigned().unwrap() as u128 * value_right.as_unsigned().unwrap() as u128
        }
        Binary::Div => {
            value_left.as_unsigned().unwrap() as u128 / value_right.as_unsigned().unwrap() as u128
        }
        Binary::SigDiv => (value_left.signed_super() / value_right.signed_super()) as u128,
        Binary::Rem => {
            value_left.as_unsigned().unwrap() as u128 % value_right.as_unsigned().unwrap() as u128
        }
        Binary::Add => {
            value_left.as_unsigned().unwrap() as u128 + value_right.as_unsigned().unwrap() as u128
        }
        Binary::Sub => (value_left.as_unsigned().unwrap() as u128)
            .wrapping_sub(value_right.as_unsigned().unwrap() as u128),
        Binary::Lsl => {
            value_left.as_unsigned().unwrap() as u128 >> value_right.as_unsigned().unwrap()
        }
        Binary::Lsr => {
            (value_left.as_unsigned().unwrap() as u128) << value_right.as_unsigned().unwrap()
        }
        Binary::Asr => {
            ((value_left.as_unsigned().unwrap() as i128) >> value_right.as_unsigned().unwrap())
                as u128
        }
        Binary::BitAnd => {
            value_left.as_unsigned().unwrap() as u128 & value_right.as_unsigned().unwrap() as u128
        }
        Binary::BitXor => {
            value_left.as_unsigned().unwrap() as u128 ^ value_right.as_unsigned().unwrap() as u128
        }
        Binary::BitOr => {
            value_left.as_unsigned().unwrap() as u128 | value_right.as_unsigned().unwrap() as u128
        }
        Binary::SigLess => (value_left.signed_super() < value_right.signed_super()) as u128,
        Binary::SigGreater => (value_left.signed_super() > value_right.signed_super()) as u128,
        Binary::SigRem => (value_left.signed_super() % value_right.signed_super()) as u128,
        Binary::SigLessEq => (value_left.signed_super() <= value_right.signed_super()) as u128,
        Binary::SigGreaterEq => (value_left.signed_super() >= value_right.signed_super()) as u128,
        Binary::Less => {
            ((value_left.as_unsigned().unwrap() as u128)
                < (value_right.as_unsigned().unwrap() as u128)) as u128
        }
        Binary::Greater => {
            ((value_left.as_unsigned().unwrap() as u128)
                > (value_right.as_unsigned().unwrap() as u128)) as u128
        }
        Binary::LessEq => {
            ((value_left.as_unsigned().unwrap() as u128)
                <= (value_right.as_unsigned().unwrap() as u128)) as u128
        }
        Binary::GreaterEq => {
            ((value_left.as_unsigned().unwrap() as u128)
                >= (value_right.as_unsigned().unwrap() as u128)) as u128
        }
        Binary::And => {
            ((value_left.signed_super() != 0) && (value_right.signed_super() != 0)) as u128
        }
        Binary::Xor => {
            ((value_left.signed_super() != 0) ^ (value_right.signed_super() != 0)) as u128
        }
        Binary::Or => {
            ((value_left.signed_super() != 0) || (value_right.signed_super() != 0)) as u128
        }
        Binary::Eq => {
            ((value_left.signed_super() != 0) == (value_right.signed_super() != 0)) as u128
        }
        Binary::Ne => {
            ((value_left.signed_super() != 0) != (value_right.signed_super() != 0)) as u128
        }
        Binary::Carry => {
            let value = ((value_left.as_unsigned().unwrap() as u128)
                + (value_right.as_unsigned().unwrap() as u128)) as u128;
            let value_max = u128::MAX >> (u128::BITS - len_left.get() as u32);
            (value > value_max) as u128
        }
        Binary::SCarry => {
            let value = value_left.signed_super() + value_right.signed_super();
            let value_max = (u128::MAX >> (u128::BITS - len_left.get() as u32)) as i128;
            (value > value_max) as u128
        }
        Binary::SBorrow => {
            let value = value_left.signed_super() - value_right.signed_super();
            let value_min = -(1 << ((len_left.get() - 1) as u32));
            (value < value_min) as u128
        }
        // TODO implement Float with arbitrary len
        Binary::FloatDiv
        | Binary::FloatMult
        | Binary::FloatAdd
        | Binary::FloatSub
        | Binary::FloatLess
        | Binary::FloatGreater
        | Binary::FloatLessEq
        | Binary::FloatGreaterEq
        | Binary::FloatEq
        | Binary::FloatNe => return None,
    };
    Some(if result > 0 {
        Number::Positive(result.try_into().ok()?)
    } else {
        Number::Negative(result.checked_neg()?.try_into().ok()?)
    })
}

fn variable_from_sleigh(variable: &sleigh_rs::execution::Variable) -> Variable {
    Variable {
        name: variable.name().to_owned(),
        len_bits: variable.len_bits,
    }
}

fn find_table_export_reference(
    sleigh_data: &Sleigh,
    sleigh_table: &sleigh_rs::table::Table,
) -> Option<sleigh_rs::SpaceId> {
    sleigh_table
        .constructors()
        .iter()
        .filter_map(|con| con.execution.as_ref())
        .flat_map(|exe| exe.export())
        // just use the first one that you find LOL
        .find_map(|expr| match expr {
            sleigh_rs::execution::Export::Value(sleigh_rs::execution::Expr::Value(
                sleigh_rs::execution::ExprElement::Value(
                    sleigh_rs::execution::ExprValue::TokenField(tf),
                ),
            )) if matches!(
                &sleigh_data.token_field(tf.id).attach,
                sleigh_rs::token::TokenFieldAttach::Varnode(_)
            ) =>
            {
                let sleigh_rs::token::TokenFieldAttach::Varnode(attach) =
                    &sleigh_data.token_field(tf.id).attach
                else {
                    unreachable!();
                };
                let varnodes = sleigh_data.attach_varnode(*attach);
                let varnode = sleigh_data.varnode(varnodes.0[0].1);
                Some(varnode.space)
            }
            sleigh_rs::execution::Export::Value(sleigh_rs::execution::Expr::Value(
                sleigh_rs::execution::ExprElement::Value(sleigh_rs::execution::ExprValue::Context(
                    ctx,
                )),
            )) if matches!(
                &sleigh_data.context(ctx.id).attach,
                sleigh_rs::varnode::ContextAttach::Varnode(_)
            ) =>
            {
                todo!()
            }
            sleigh_rs::execution::Export::Value(sleigh_rs::execution::Expr::Value(
                sleigh_rs::execution::ExprElement::Value(sleigh_rs::execution::ExprValue::Varnode(
                    varnode,
                )),
            )) => {
                let varnode = sleigh_data.varnode(varnode.id);
                Some(varnode.space)
            }
            sleigh_rs::execution::Export::Value(sleigh_rs::execution::Expr::Value(
                sleigh_rs::execution::ExprElement::Value(
                    sleigh_rs::execution::ExprValue::Bitrange(bitrange),
                ),
            )) => {
                let bitrange = sleigh_data.bitrange(bitrange.id);
                let varnode = sleigh_data.varnode(bitrange.varnode);
                Some(varnode.space)
            }
            sleigh_rs::execution::Export::Reference { addr: _, memory } => Some(memory.space),
            sleigh_rs::execution::Export::Const { .. } | sleigh_rs::execution::Export::Value(_) => {
                None
            }
        })
}

fn try_find_varnode_at(
    sleigh: &Sleigh,
    addr: u64,
    bytes: NumberNonZeroUnsigned,
) -> Result<VarnodeId, ()> {
    let varnode_id = sleigh
        .varnodes()
        .iter()
        .position(|v| v.address == addr && v.len_bytes == bytes)
        .ok_or(())?;
    Ok(unsafe { VarnodeId::from_raw(varnode_id) })
}
