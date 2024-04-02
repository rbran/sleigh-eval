use std::path::{Path, PathBuf};

use sleigh_eval::*;

use sleigh_rs::{ContextId, Sleigh};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        //parse_all();
        test_x86_64();
    });
}

#[allow(dead_code)]
fn ghidra_home() -> PathBuf {
    let var = std::env::var("GHIDRA_SRC").expect("Enviroment variable GHIDRA_SRC not found");
    PathBuf::from(var)
}

#[allow(dead_code)]
fn test_x86_64() {
    const INSTRS: &[&[u8]] = &[
        // 90                   nop
        &[0x90],
        // 31 c0                xor    %eax,%eax
        &[0x31, 0xc0],
        // 31 f6                xor    %esi,%esi
        &[0x31, 0xf6],
        // 5b                   pop    %ebx
        &[0x5b],
        // c3                   ret
        &[0xc3],
    ];

    const SLEIGH_FILE: &str = "Ghidra/Processors/x86/data/languages/x86-64.slaspec";

    let path = ghidra_home().join(SLEIGH_FILE);
    let sleigh_data = match file_to_sleigh(&path) {
        Ok(data) => data,
        Err(e) => panic!("Error: {e}"),
    };
    let mut context = new_default_context(&sleigh_data);
    set_context_name(&sleigh_data, &mut context, "longMode", 0);
    set_context_name(&sleigh_data, &mut context, "bit64", 0);
    set_context_name(&sleigh_data, &mut context, "addrsize", 1);
    set_context_name(&sleigh_data, &mut context, "opsize", 1);
    for instr in INSTRS {
        let instruction = match_instruction(&sleigh_data, context.clone(), 0, instr).unwrap();
        let constructor = sleigh_data
            .table(sleigh_data.instruction_table)
            .constructor(instruction.constructor.entry.constructor);
        assert_eq!(instr.len(), instruction.constructor.len);
        println!("instruction {}", &constructor.location);
        println!(
            "Disassembly {}",
            to_string_instruction(&sleigh_data, &context, 0, &instruction)
        );
    }
}

#[allow(dead_code)]
fn set_context_name(sleigh: &Sleigh, context: &mut [u8], name: &str, value: u128) {
    let context_var = sleigh
        .contexts()
        .iter()
        .position(|c| c.name() == name)
        .map(ContextId)
        .unwrap();
    set_context_field_value(sleigh, context, context_var, value);
}

#[allow(dead_code)]
fn parse_all() {
    const ARCHS: &[&str] = &[
        "RISCV/data/languages/riscv.lp64d.slaspec",
        "RISCV/data/languages/riscv.ilp32d.slaspec",
        "DATA/data/languages/data-le-64.slaspec",
        "DATA/data/languages/data-be-64.slaspec",
        "V850/data/languages/V850.slaspec",
        "68000/data/languages/68040.slaspec",
        "68000/data/languages/68030.slaspec",
        "68000/data/languages/coldfire.slaspec",
        "68000/data/languages/68020.slaspec",
        "SuperH4/data/languages/SuperH4_le.slaspec",
        "SuperH4/data/languages/SuperH4_be.slaspec",
        "6502/data/languages/6502.slaspec",
        "6502/data/languages/65c02.slaspec",
        "CR16/data/languages/CR16B.slaspec",
        "CR16/data/languages/CR16C.slaspec",
        "BPF/data/languages/BPF_le.slaspec",
        "Z80/data/languages/z80.slaspec",
        "Z80/data/languages/z180.slaspec",
        "M8C/data/languages/m8c.slaspec",
        "8051/data/languages/80390.slaspec",
        "8051/data/languages/80251.slaspec",
        "8051/data/languages/8051.slaspec",
        "8051/data/languages/mx51.slaspec",
        "PIC/data/languages/pic12c5xx.slaspec",
        "PIC/data/languages/dsPIC30F.slaspec",
        "PIC/data/languages/pic17c7xx.slaspec",
        "PIC/data/languages/PIC24H.slaspec",
        "PIC/data/languages/pic16c5x.slaspec",
        "PIC/data/languages/dsPIC33E.slaspec",
        "PIC/data/languages/pic16.slaspec",
        "PIC/data/languages/dsPIC33C.slaspec",
        "PIC/data/languages/PIC24E.slaspec",
        "PIC/data/languages/PIC24F.slaspec",
        "PIC/data/languages/dsPIC33F.slaspec",
        "PIC/data/languages/pic18.slaspec",
        "PIC/data/languages/pic16f.slaspec",
        "HCS08/data/languages/HCS08.slaspec",
        "HCS08/data/languages/HC08.slaspec",
        "HCS08/data/languages/HC05.slaspec",
        "eBPF/data/languages/eBPF_le.slaspec",
        "AARCH64/data/languages/AARCH64.slaspec",
        "AARCH64/data/languages/AARCH64BE.slaspec",
        "AARCH64/data/languages/AARCH64_AppleSilicon.slaspec",
        "tricore/data/languages/tricore.slaspec",
        "PA-RISC/data/languages/pa-risc32be.slaspec",
        "MC6800/data/languages/6809.slaspec",
        "MC6800/data/languages/6805.slaspec",
        "MC6800/data/languages/H6309.slaspec",
        "TI_MSP430/data/languages/TI_MSP430X.slaspec",
        "TI_MSP430/data/languages/TI_MSP430.slaspec",
        "PowerPC/data/languages/ppc_32_quicciii_le.slaspec",
        "PowerPC/data/languages/ppc_64_isa_be.slaspec",
        "PowerPC/data/languages/ppc_64_isa_altivec_vle_be.slaspec",
        "PowerPC/data/languages/ppc_32_e500_be.slaspec",
        "PowerPC/data/languages/ppc_64_isa_altivec_be.slaspec",
        "PowerPC/data/languages/ppc_32_be.slaspec",
        "PowerPC/data/languages/ppc_64_be.slaspec",
        "PowerPC/data/languages/ppc_32_4xx_le.slaspec",
        "PowerPC/data/languages/ppc_32_quicciii_be.slaspec",
        "PowerPC/data/languages/ppc_32_4xx_be.slaspec",
        "PowerPC/data/languages/ppc_64_isa_altivec_le.slaspec",
        "PowerPC/data/languages/ppc_32_le.slaspec",
        "PowerPC/data/languages/ppc_64_isa_le.slaspec",
        "PowerPC/data/languages/ppc_64_le.slaspec",
        "PowerPC/data/languages/ppc_32_e500_le.slaspec",
        "PowerPC/data/languages/ppc_64_isa_vle_be.slaspec",
        "MIPS/data/languages/mips32R6be.slaspec",
        "MIPS/data/languages/mips64be.slaspec",
        "MIPS/data/languages/mips32R6le.slaspec",
        "MIPS/data/languages/mips32le.slaspec",
        "MIPS/data/languages/mips64le.slaspec",
        "MIPS/data/languages/mips32be.slaspec",
        "Atmel/data/languages/avr32a.slaspec",
        "Atmel/data/languages/avr8.slaspec",
        "Atmel/data/languages/avr8xmega.slaspec",
        "Atmel/data/languages/avr8e.slaspec",
        "Atmel/data/languages/avr8eind.slaspec",
        "x86/data/languages/x86.slaspec",
        "x86/data/languages/x86-64.slaspec",
        "CP1600/data/languages/CP1600.slaspec",
        "SuperH/data/languages/sh-2.slaspec",
        "SuperH/data/languages/sh-2a.slaspec",
        "SuperH/data/languages/sh-1.slaspec",
        "Sparc/data/languages/SparcV9_64.slaspec",
        "Sparc/data/languages/SparcV9_32.slaspec",
        "MCS96/data/languages/MCS96.slaspec",
        "Toy/data/languages/toy64_le.slaspec",
        "Toy/data/languages/toy_builder_be_align2.slaspec",
        "Toy/data/languages/toy_be_posStack.slaspec",
        "Toy/data/languages/toy_builder_be.slaspec",
        "Toy/data/languages/toy_wsz_be.slaspec",
        "Toy/data/languages/toy_le.slaspec",
        "Toy/data/languages/toy64_be_harvard.slaspec",
        "Toy/data/languages/toy64_be.slaspec",
        "Toy/data/languages/toy_wsz_le.slaspec",
        "Toy/data/languages/toy_builder_le.slaspec",
        "Toy/data/languages/toy_be.slaspec",
        "Toy/data/languages/toy_builder_le_align2.slaspec",
        "ARM/data/languages/ARM4t_le.slaspec",
        "ARM/data/languages/ARM4_le.slaspec",
        "ARM/data/languages/ARM7_be.slaspec",
        "ARM/data/languages/ARM6_be.slaspec",
        "ARM/data/languages/ARM5t_le.slaspec",
        "ARM/data/languages/ARM5_le.slaspec",
        "ARM/data/languages/ARM4_be.slaspec",
        "ARM/data/languages/ARM5_be.slaspec",
        "ARM/data/languages/ARM4t_be.slaspec",
        "ARM/data/languages/ARM7_le.slaspec",
        "ARM/data/languages/ARM6_le.slaspec",
        "ARM/data/languages/ARM5t_be.slaspec",
        "ARM/data/languages/ARM8_le.slaspec",
        "ARM/data/languages/ARM8_be.slaspec",
        "8085/data/languages/8085.slaspec",
        "HCS12/data/languages/HCS12X.slaspec",
        "HCS12/data/languages/HC12.slaspec",
        "HCS12/data/languages/HCS12.slaspec",
        "8048/data/languages/8048.slaspec",
        // TODO: cpool
        //"JVM/data/languages/JVM.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Oreo.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Android10.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Marshmallow.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Pie.slaspec",
        //"Dalvik/data/languages/Dalvik_ODEX_KitKat.slaspec",
        //"Dalvik/data/languages/Dalvik_Base.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_KitKat.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Android11.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Nougat.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Android12.slaspec",
        //"Dalvik/data/languages/Dalvik_DEX_Lollipop.slaspec",
    ];
    const SLEIGH_PROCESSOR_PATH: &str = "Ghidra/Processors";
    let home = ghidra_home();
    let path = home.to_string_lossy();
    for arch in ARCHS {
        let file = format!("{path}/{SLEIGH_PROCESSOR_PATH}/{arch}");
        let path = Path::new(&file);
        println!("parsing: {}", path.file_name().unwrap().to_str().unwrap());

        if let Err(err) = file_to_sleigh(path) {
            println!("Unable to parse: {err}");
        } else {
            println!("Success");
        }
    }
}
