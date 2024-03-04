use std::path::Path;

use sleigh_eval::*;

fn main() {
    // 90                   nop
    #[allow(dead_code)]
    const NOP: &[u8] = &[0x90];
    // 31 c0                xor    %eax,%eax
    #[allow(dead_code)]
    const XOR_EAX: &[u8] = &[0x31, 0xc0];
    // 31 f6                xor    %esi,%esi
    #[allow(dead_code)]
    const XOR_ESI: &[u8] = &[0x31, 0xf6];
    // c3                   ret
    #[allow(dead_code)]
    const RET: &[u8] = &[0xce];
    // 5b                   pop    %rbx
    #[allow(dead_code)]
    const POP_RBX: &[u8] = &[0x5b];

    const SLEIGH_FILE: &str =
        "/home/rbran/src/ghidra/Ghidra/Processors/x86/data/languages/x86.slaspec";

    let sleigh_data = file_to_sleigh(Path::new(SLEIGH_FILE)).unwrap();
    let mut context = new_default_context(&sleigh_data);
    let _instruction = match_instruction(&sleigh_data, &mut context, 0, NOP).unwrap();
}
