//! The analyses for x86(_64)
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fs::{self, File},
    io::{self, BufRead},
    time::Instant,
};

use capstone::{arch::x86::X86Insn, prelude::*};

use crate::common::{AnalysisOptions, Jump, Summary};

/// The `x86_64` `JMPscare` analysis
#[allow(clippy::too_many_lines)]
pub fn analyze_x86(opts: &AnalysisOptions) -> Summary {
    println!("[+] Starting Analysis of x86_64 Trace");
    let now = Instant::now();

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object for x86_64");

    let mut jump_map: HashMap<u64, Jump> = HashMap::new();
    let mut last_jmp_addr: u64 = 0;

    let mut num_traces = 0;
    let mut num_jumps = 0;
    let mut ignore_list = HashSet::new();

    println!(
        " >  Finding Uni-Directional Jumps in {} Execution Traces",
        fs::read_dir(&opts.trace_path)
            .expect("Reading directory contents failed")
            .count()
    );
    for entry in fs::read_dir(&opts.trace_path).expect("Reading directory contents failed") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            let curr_file = path.to_str().unwrap();
            let fd = File::open(curr_file).expect("Failed to open file");
            num_traces += 1;

            for line in io::BufReader::new(fd).lines().map_while(Result::ok) {
                if line.starts_with('#') || line.trim().is_empty() {
                    // Ignore comments and empty lines.
                    continue;
                }

                let addr = u64::from_str_radix(line.trim_start_matches("0x"), 16).unwrap();
                let disas = cs
                    .disasm_count(
                        &opts.binary[usize::try_from(addr - opts.offset).unwrap()..],
                        addr,
                        1,
                    )
                    .unwrap();

                // check target of last jump
                if last_jmp_addr != 0 {
                    let last_jmp = jump_map.get_mut(&last_jmp_addr).unwrap();
                    if !last_jmp.taken && addr == last_jmp.target {
                        last_jmp.taken = true;
                    } else if !last_jmp.not_taken && addr != last_jmp.target {
                        last_jmp.not_taken = true;
                    }

                    last_jmp_addr = 0;
                }

                let insn = disas.iter().next();
                let Some(insn) = insn else {
                    if ignore_list.contains(&addr) {
                        continue;
                    }
                    println!("[!] Failed to disassemble at address {addr:#x}\n    Add to ignore list? [Y]es/[N]o/[A]bort");
                    let mut input = String::new();
                    std::io::stdin()
                        .read_line(&mut input)
                        .expect("failed to read user input");
                    input = input.to_lowercase();
                    if &input[0..1] == "a" {
                        panic!();
                    } else if &input[0..1] == "y" {
                        ignore_list.insert(addr);
                        continue;
                    } else {
                        continue;
                    }
                };

                if insn.id().0 >= X86Insn::X86_INS_JAE as u32
                    && insn.id().0 <= X86Insn::X86_INS_JP as u32
                {
                    // branch
                    num_jumps += 1;
                    let mnemonic = insn.mnemonic().unwrap();

                    // conditional branch
                    if mnemonic != "jmp" {
                        let t = u64::from_str_radix(
                            insn.op_str().unwrap().split("0x").nth(1).unwrap().trim(),
                            16,
                        )
                        .unwrap();

                        jump_map.entry(addr).or_insert_with(|| {
                            let new_jmp = Jump {
                                taken: false,
                                not_taken: false,
                                condition: String::from(mnemonic.split('j').nth(1).unwrap()),
                                target: t,
                                insn_size: u8::try_from(insn.bytes().len()).unwrap(),
                                mode: 0,
                                pnc: 0,
                            };
                            new_jmp
                        });

                        last_jmp_addr = addr;
                    }
                }
            }
        }
    }

    let num_uniq_jumps = jump_map.len() as u64;

    Summary {
        time: now.elapsed(),
        num_traces,
        total_jumps: num_jumps,
        unique_jumps: num_uniq_jumps,
        jumps: jump_map,
        // TODO: Add possible new coverage analysis support
        pnc: 0,
    }
}
