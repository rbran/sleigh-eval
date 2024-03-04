use std::path::Path;

use sleigh_eval::*;

fn main() {
    const INSTRS: &[&[u8]] = &[
        // 90                   nop
        &[0x90],
        // 31 c0                xor    %eax,%eax
        &[0x31, 0xc0],
        // 31 f6                xor    %esi,%esi
        &[0x31, 0xf6],
        // 5b                   pop    %rbx
        &[0x5b],
        // c3                   ret
        &[0xc3],
    ];

    const SLEIGH_FILE: &str =
        "/home/rbran/src/ghidra/Ghidra/Processors/x86/data/languages/x86-64.slaspec";

    let sleigh_data = file_to_sleigh(Path::new(SLEIGH_FILE)).unwrap();
    let mut context = new_default_context(&sleigh_data);
    for instr in INSTRS {
        let instruction = match_instruction(&sleigh_data, &mut context, 0, instr).unwrap();
        let constructor = sleigh_data
            .table(sleigh_data.instruction_table)
            .constructor(instruction.entry.constructor);
        let mneumonic = constructor.display.mneumonic.as_deref().unwrap_or("PSEUDO");
        assert_eq!(instr.len(), instruction.len);
        println!("instruction {} {}", mneumonic, &constructor.location);
    }
}
