//! The analyses for ARM
use capstone::{arch::arm::ArmInsn, prelude::*};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{self, BufRead},
    time::Instant,
};

use crate::common::{check_bb_cov, find_ud_jumps, AnalysisOptions, BasicBlock, Jump, Summary};

/// traverse basic blocks to analyze potential new coverage
fn check_potential_new_cov(
    cs: Capstone,
    jumps: &mut HashMap<u64, Jump>,
    blocks: &mut HashMap<u64, BasicBlock>,
    opts: AnalysisOptions,
) -> u32 {
    println!(" >  Analyzing Potential New Coverage");
    let mut all_tainted_blocks = blocks.clone();
    let mut total_new_blocks = jumps.len();

    for (k, v) in jumps.iter_mut() {
        let mut i = 0;
        let mut new_blocks: u32 = 1;
        let mut curr_blocks = blocks.clone(); // reset tainted blocks
        let mut new_edges: Vec<u64> = Vec::new();
        let mut curr_edges: Vec<u64>;
        let mut function_calls: Vec<u64> = Vec::new();

        new_edges.push(if v.taken {
            *k + v.insn_size as u64
        } else {
            v.target
        });
        // traverse edges n times
        while i < opts.n_jumps {
            curr_edges = new_edges.to_owned();
            new_edges.clear();

            for edge in curr_edges {
                let mut next_insn_addr = edge;
                loop {
                    let disas: capstone::Instructions;
                    disas = cs
                        .disasm_count(
                            &opts.binary[(next_insn_addr - opts.offset) as usize..],
                            next_insn_addr,
                            1,
                        )
                        .unwrap();
                    let insn = disas.iter().next();
                    let insn = match insn {
                        Some(i) => i,
                        None => break,
                    };

                    // edge discovered (i.e. jump/branch)
                    if (insn.id().0 >= ArmInsn::ARM_INS_BL as u32
                        && insn.id().0 <= ArmInsn::ARM_INS_B as u32)
                        || insn.id().0 == ArmInsn::ARM_INS_CBNZ as u32
                        || insn.id().0 == ArmInsn::ARM_INS_CBZ as u32
                    {
                        let target_0: u64 = u64::from_str_radix(
                            insn.op_str()
                                .unwrap()
                                .split("0x")
                                .nth(1)
                                .unwrap_or("")
                                .trim(),
                            16,
                        )
                        .unwrap_or(u64::MAX); // jump taken

                        // check if we have decoded an actual address (and not encountered a register branch or POP)
                        if target_0 != u64::MAX {
                            // ignore edges to already discovered basic blocks
                            if !curr_blocks.contains_key(&target_0) {
                                new_edges.push(target_0);
                                new_blocks += 1;
                                if !all_tainted_blocks.contains_key(&target_0) {
                                    total_new_blocks += 1;
                                }
                            }
                        } else {
                            // register unresolvable function calls (e.g. 'blx r3')
                            if (insn.id().0 == ArmInsn::ARM_INS_BL as u32
                                || insn.id().0 == ArmInsn::ARM_INS_BLX as u32)
                                && !function_calls.contains(&next_insn_addr)
                            {
                                new_blocks += opts.call_weight as u32;
                                total_new_blocks += 1;
                                // remember curr addr to avoid double logging
                                function_calls.push(next_insn_addr);
                            }
                        }

                        // if conditional branch or function call, add following instruction as new edge
                        let mnemonic = insn.mnemonic().unwrap();
                        if (insn.id().0 == ArmInsn::ARM_INS_BL as u32
                            || insn.id().0 == ArmInsn::ARM_INS_BLX as u32)
                            || (mnemonic.len() > 2 && &mnemonic[1..2] != ".")
                        {
                            let target_1: u64 = next_insn_addr + insn.bytes().len() as u64; // jump not taken
                            if !curr_blocks.contains_key(&target_1) {
                                new_edges.push(target_1);
                                new_blocks += 1;
                                if !all_tainted_blocks.contains_key(&target_1) {
                                    total_new_blocks += 1;
                                }
                            }
                        }

                        // add current BB
                        let new_bb = BasicBlock {
                            entry: edge,
                            exit: next_insn_addr,
                        };
                        curr_blocks.insert(edge, new_bb.clone());
                        all_tainted_blocks.insert(edge, new_bb);
                        break;
                    } else if insn.id().0 == ArmInsn::ARM_INS_POP as u32 {
                        // break on POP
                        if insn.op_str().unwrap().contains("pc") {
                            let new_bb = BasicBlock {
                                entry: edge,
                                exit: next_insn_addr,
                            };
                            curr_blocks.insert(edge, new_bb.clone());
                            all_tainted_blocks.insert(edge, new_bb);
                            break;
                        }
                    } else if insn.id().0 == ArmInsn::ARM_INS_LDR as u32 {
                        // break on LDR PC
                        if insn.op_str().unwrap().contains("pc, [") {
                            let new_bb = BasicBlock {
                                entry: edge,
                                exit: next_insn_addr,
                            };
                            curr_blocks.insert(edge, new_bb.clone());
                            all_tainted_blocks.insert(edge, new_bb);
                            break;
                        }
                    }

                    next_insn_addr = next_insn_addr + insn.bytes().len() as u64;
                }
            }
            i += 1;
        }
        v.pnc = new_blocks;
    }

    return total_new_blocks as _;
}

/// The arm JMPscare analysis
pub fn analyze_arm(opts: AnalysisOptions) -> Summary {
    println!("[*] Starting Analysis of ARM Trace");
    let now = Instant::now();

    let cs = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Arm)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object for ARM");
    let cs_t = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object for thumb mode");

    let mut jump_map: HashMap<u64, Jump> = HashMap::new();
    let mut bb_bucket: HashMap<u64, BasicBlock> = HashMap::new();
    let mut last_jmp_addr: u64 = 0;
    let mut curr_bb: u64 = 0;

    let mut num_traces = 0;
    let mut num_jumps = 0;
    let mut ignore_list = HashSet::new();

    println!(
        " >  Finding Uni-Directional Jumps in {} Execution Traces",
        fs::read_dir(opts.trace_path)
            .expect("Reading directory contents failed")
            .count()
    );
    for entry in fs::read_dir(opts.trace_path).expect("Reading directory contents failed") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            let curr_file = path.to_str().unwrap();
            let fd = File::open(curr_file).expect("Failed to open file");
            num_traces += 1;

            for line in io::BufReader::new(fd).lines() {
                if let Ok(l) = line {
                    let mut addr = u64::from_str_radix(&l.trim_start_matches("0x"), 16).unwrap();
                    let mode;

                    // try to get basic block for current addr or create new BasicBlock if none is set
                    if curr_bb == 0 {
                        let exists: bool = bb_bucket.contains_key(&addr);
                        if exists {
                            curr_bb = bb_bucket.get(&addr).unwrap().entry;
                        } else {
                            curr_bb = addr - 1;
                        }
                    }

                    let disas: capstone::Instructions;
                    if addr % 2 == 0 {
                        disas = cs
                            .disasm_count(&opts.binary[(addr - opts.offset) as usize..], addr, 1)
                            .unwrap();
                        mode = 0;
                    } else {
                        // Requirement: trace addresses of instructions in thumb mode have the LSB set to 1
                        addr -= 1;
                        disas = cs_t
                            .disasm_count(&opts.binary[(addr - opts.offset) as usize..], addr, 1)
                            .unwrap();
                        mode = 1;
                    }

                    // check target of last jump
                    if last_jmp_addr != 0 {
                        let last_jmp = jump_map.get_mut(&last_jmp_addr).unwrap();
                        if last_jmp.taken == false && addr == last_jmp.target {
                            last_jmp.taken = true;
                        } else if last_jmp.not_taken == false && addr != last_jmp.target {
                            last_jmp.not_taken = true;
                        }

                        last_jmp_addr = 0;
                    }

                    let insn = disas.iter().next();
                    let insn = match insn {
                        Some(i) => i,
                        None => {
                            if ignore_list.contains(&addr) {
                                continue;
                            } else {
                                if opts.skip_warnings {
                                    ignore_list.insert(addr);
                                    continue;
                                } else {
                                    println!("[!] Failed to disassemble at address {:#x}\n    Add to ignore list? [Y]es/[N]o/[A]bort", addr);
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
                                }
                            }
                        }
                    };

                    if insn.id().0 == ArmInsn::ARM_INS_B as u32 {
                        // branch
                        num_jumps += 1;
                        let mnemonic = insn.mnemonic().unwrap();

                        // conditional branch
                        if mnemonic.len() > 2 && mnemonic != "blx" && &mnemonic[1..2] != "." {
                            let t = u64::from_str_radix(
                                &disas.to_string().split("#0x").nth(1).unwrap().trim(),
                                16,
                            )
                            .unwrap();

                            if !jump_map.contains_key(&addr) {
                                let new_jmp = Jump {
                                    taken: false,
                                    not_taken: false,
                                    condition: String::from(&mnemonic[1..3]),
                                    target: t,
                                    insn_size: insn.bytes().len() as u8,
                                    mode: mode,
                                    pnc: 0,
                                };
                                jump_map.insert(addr, new_jmp);
                            }

                            last_jmp_addr = addr;
                        }
                    }

                    // close basic block on jump
                    if insn.id().0 >= ArmInsn::ARM_INS_BL as u32 && insn.id().0 <= ArmInsn::ARM_INS_B as u32 || // BL, BX, BXL, BXJ, B
                       insn.id().0 >= ArmInsn::ARM_INS_CBNZ as u32 && insn.id().0 <= ArmInsn::ARM_INS_POP as u32
                    {
                        // CBNZ, CBZ, POP
                        let new_bb = BasicBlock {
                            entry: curr_bb,
                            exit: addr,
                        };
                        bb_bucket.insert(curr_bb, new_bb);
                        curr_bb = 0;
                    }
                }
            }
        }
    }

    let num_uniq_jumps = jump_map.len() as u64;
    find_ud_jumps(&mut jump_map);
    check_bb_cov(&mut jump_map, &bb_bucket);
    let pnc = check_potential_new_cov(cs_t, &mut jump_map, &mut bb_bucket, opts);

    let result = Summary {
        time: now.elapsed(),
        num_traces: num_traces,
        total_jumps: num_jumps,
        unique_jumps: num_uniq_jumps,
        jumps: jump_map,
        pnc: pnc,
    };

    return result;
}
