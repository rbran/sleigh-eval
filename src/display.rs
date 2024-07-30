// use sleigh_rs::{Number, ValueFmt, VarnodeId};

use sleigh_rs::{NumberSuperSigned, NumberUnsigned, PrintBase, VarnodeId};

use crate::{get_context_field_value, ConstructorMatch, InstructionMatch};

pub(crate) struct DisplayConstructor<'a> {
    inst_start: u64,
    instruction: &'a InstructionMatch,
    display: Display<'a>,
}

#[derive(Clone, Debug)]
pub struct Display<'a> {
    sleigh_data: &'a sleigh_rs::Sleigh,
    pub mneumonic: Option<String>,
    pub elements: Vec<DisplayElement>,
}

#[derive(Clone, Debug)]
pub enum DisplayElement {
    Separator,
    Literal(String),
    Varnode(VarnodeId),
    Number(NumberSuperSigned, PrintBase),
    Address(NumberUnsigned),
}

impl<'a> DisplayConstructor<'a> {
    pub fn new(
        sleigh_data: &'a sleigh_rs::Sleigh,
        inst_start: u64,
        instruction: &'a InstructionMatch,
    ) -> Self {
        Self {
            inst_start,
            instruction,
            display: Display {
                sleigh_data,
                mneumonic: None,
                elements: Default::default(),
            },
        }
    }

    pub fn to_tokens(mut self) -> Display<'a> {
        let instruction_table_id = self.instruction.constructor.table_id;
        let table = self.display.sleigh_data.table(instruction_table_id);
        let matched = &self.instruction.constructor;
        let constructor = table.constructor(matched.entry.constructor);
        self.display.mneumonic = constructor.display.mneumonic.as_ref().cloned();
        self.inline_constructor(instruction_table_id, matched);
        self.display
    }

    fn inline_constructor(&mut self, table: sleigh_rs::TableId, matched: &ConstructorMatch) {
        use sleigh_rs::display::DisplayElement::*;
        let table = self.display.sleigh_data.table(table);
        let constructor = table.constructor(matched.entry.constructor);
        for element in constructor.display.elements() {
            match element {
                Varnode(varnode) => self
                    .display
                    .elements
                    .push(DisplayElement::Varnode(*varnode)),
                Context(var) => {
                    let value = get_context_field_value(
                        self.display.sleigh_data,
                        &self.instruction.context,
                        *var,
                    );
                    let context = self.display.sleigh_data.context(*var);
                    self.inline_meaning(context.meaning(), value);
                }
                TokenField(var) => {
                    let value = matched.token_fields.get(var).unwrap();
                    let tf = self.display.sleigh_data.token_field(*var);
                    self.inline_meaning(tf.meaning(), *value);
                }
                InstStart(_) => self
                    .display
                    .elements
                    .push(DisplayElement::Address(self.inst_start)),
                InstNext(_) => self.display.elements.push(DisplayElement::Address(
                    self.inst_start + u64::try_from(matched.len).unwrap(),
                )),
                Table(sub_table) => {
                    let matched_sub_table = matched.sub_tables.get(sub_table).unwrap();
                    self.inline_constructor(*sub_table, matched_sub_table);
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
                    self.display
                        .elements
                        .push(DisplayElement::Number(value, sleigh_rs::PrintBase::Hex));
                }
                Literal(lit) => self
                    .display
                    .elements
                    .push(DisplayElement::Literal(lit.to_owned())),
                Space => self.display.elements.push(DisplayElement::Separator),
            }
        }
    }

    fn inline_meaning(&mut self, meaning: sleigh_rs::meaning::Meaning, value: i128) {
        match meaning {
            sleigh_rs::meaning::Meaning::NoAttach(fmt) => self
                .display
                .elements
                .push(DisplayElement::Number(value, fmt.base)),
            sleigh_rs::meaning::Meaning::Varnode(varnodes_id) => {
                let varnodes = self.display.sleigh_data.attach_varnode(varnodes_id);
                let varnode_id = varnodes.find_value(value.try_into().unwrap());
                self.display
                    .elements
                    .push(DisplayElement::Varnode(varnode_id.unwrap()));
            }
            sleigh_rs::meaning::Meaning::Literal(literals_id) => {
                let literals = self.display.sleigh_data.attach_literal(literals_id);
                let literal = literals.find_value(value.try_into().unwrap());
                self.display
                    .elements
                    .push(DisplayElement::Literal(literal.unwrap().to_owned()));
            }
            sleigh_rs::meaning::Meaning::Number(base, values_id) => {
                let values = self.display.sleigh_data.attach_number(values_id);
                let value = values.find_value(value.try_into().unwrap());
                self.display
                    .elements
                    .push(DisplayElement::Number(value.unwrap().signed_super(), base));
            }
        }
    }
}

impl std::fmt::Display for Display<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(mneumonic) = &self.mneumonic {
            write!(f, "{}", mneumonic)?;
        }
        for element in &self.elements {
            match element {
                DisplayElement::Separator => write!(f, " ")?,
                DisplayElement::Literal(lit) => write!(f, "{}", lit)?,
                DisplayElement::Varnode(varnode_id) => {
                    let varnode = self.sleigh_data.varnode(*varnode_id);
                    write!(f, "{}", varnode.name())?;
                }
                DisplayElement::Number(value, base) => match base {
                    PrintBase::Dec => write!(f, "{value}")?,
                    PrintBase::Hex => write!(f, "{value:#x}")?,
                },
                DisplayElement::Address(addr) => write!(f, "{addr:#x}")?,
            }
        }
        Ok(())
    }
}
