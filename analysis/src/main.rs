extern crate clap;
use capstone::{
    arch::{arm::ArmInsn, mips::MipsInsn, x86::X86Insn},
    prelude::*,
};
use clap::{App, Arg};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    time::Instant,
};

#[derive(Debug)]
pub struct Jump {
    taken: bool,
    not_taken: bool,
    condition: String,
    target: u64,
    insn_size: u8,
    mode: u8,
    pnc: u32,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    entry: u64,
    exit: u64,
}

#[derive(Debug)]
pub struct Summary {
    time: u64,
    num_traces: u64,
    total_jumps: u64,
    unique_jumps: u64,
    jumps: HashMap<u64, Jump>,
    pnc: u32,
}

#[derive(Debug)]
pub struct AnalysisOptions<'a> {
    binary: Vec<u8>,
    offset: u64,
    trace_path: &'a str,
    verbosity_lvl: u8,
    skip_warnings: bool,
    n_jumps: u32,
    call_weight: u8,
}

const MIPS_BRANCHES: [u32; 46] = [
    MipsInsn::MIPS_INS_BEQ as u32,
    MipsInsn::MIPS_INS_BEQC as u32,
    MipsInsn::MIPS_INS_BEQL as u32,
    MipsInsn::MIPS_INS_BEQZ16 as u32,
    MipsInsn::MIPS_INS_BEQZALC as u32,
    MipsInsn::MIPS_INS_BEQZC as u32,
    MipsInsn::MIPS_INS_BGEC as u32,
    MipsInsn::MIPS_INS_BGEUC as u32,
    MipsInsn::MIPS_INS_BGEZ as u32,
    MipsInsn::MIPS_INS_BGEZAL as u32,
    MipsInsn::MIPS_INS_BGEZALC as u32,
    MipsInsn::MIPS_INS_BGEZALL as u32,
    MipsInsn::MIPS_INS_BGEZALS as u32,
    MipsInsn::MIPS_INS_BGEZC as u32,
    MipsInsn::MIPS_INS_BGEZL as u32,
    MipsInsn::MIPS_INS_BGTZ as u32,
    MipsInsn::MIPS_INS_BGTZALC as u32,
    MipsInsn::MIPS_INS_BGTZC as u32,
    MipsInsn::MIPS_INS_BGTZL as u32,
    MipsInsn::MIPS_INS_BLEZ as u32,
    MipsInsn::MIPS_INS_BLEZALC as u32,
    MipsInsn::MIPS_INS_BLEZC as u32,
    MipsInsn::MIPS_INS_BLEZL as u32,
    MipsInsn::MIPS_INS_BLTC as u32,
    MipsInsn::MIPS_INS_BLTUC as u32,
    MipsInsn::MIPS_INS_BLTZ as u32,
    MipsInsn::MIPS_INS_BLTZAL as u32,
    MipsInsn::MIPS_INS_BLTZALC as u32,
    MipsInsn::MIPS_INS_BLTZALL as u32,
    MipsInsn::MIPS_INS_BLTZALS as u32,
    MipsInsn::MIPS_INS_BLTZC as u32,
    MipsInsn::MIPS_INS_BLTZL as u32,
    MipsInsn::MIPS_INS_BNE as u32,
    MipsInsn::MIPS_INS_BNEC as u32,
    MipsInsn::MIPS_INS_BNEGI as u32,
    MipsInsn::MIPS_INS_BNEG as u32,
    MipsInsn::MIPS_INS_BNEL as u32,
    MipsInsn::MIPS_INS_BNEZ16 as u32,
    MipsInsn::MIPS_INS_BNEZALC as u32,
    MipsInsn::MIPS_INS_BNEZC as u32,
    MipsInsn::MIPS_INS_BNVC as u32,
    MipsInsn::MIPS_INS_BOVC as u32,
    MipsInsn::MIPS_INS_BNZ as u32,
    MipsInsn::MIPS_INS_BZ as u32,
    MipsInsn::MIPS_INS_BEQZ as u32,
    MipsInsn::MIPS_INS_BNE as u32,
];

// write analysis report to file, to be parsed by JMPscare disassembler plugins
fn generate_output(jumps: &HashMap<u64, Jump>, file_name: &str) {
    println!(" >  Generating Output File");
    let mut file = File::create(file_name.to_string()).expect("Failed to create file");
    for (k, v) in jumps.iter() {
        let s = if v.taken {
            "ALWAYS_TAKEN"
        } else {
            "NEVER_TAKEN"
        };
        let line = format!(
            "{:#X} CONDITION_{} {} {}\n",
            k,
            v.condition.to_uppercase(),
            s,
            v.pnc
        );
        file.write(line.as_bytes())
            .expect("Failed to write to file");
    }
}

// filter for uni-directional jumps
fn find_ud_jumps(jumps: &mut HashMap<u64, Jump>) {
    jumps.retain(|_k, v| v.taken != v.not_taken)
}

// reduce noise (check if basic block behind uni-directional jump has coverage)
fn check_bb_cov(jumps: &mut HashMap<u64, Jump>, blocks: &HashMap<u64, BasicBlock>) {
    jumps.retain(|k, v| {
        let not_visited = if v.taken {
            *k + v.insn_size as u64
        } else {
            v.target
        };
        !blocks.contains_key(&not_visited)
    })
}

// traverse basic blocks to analyze potential new coverage
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

fn analyze_arm(opts: AnalysisOptions) -> Summary {
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
        time: now.elapsed().as_secs(),
        num_traces: num_traces,
        total_jumps: num_jumps,
        unique_jumps: num_uniq_jumps,
        jumps: jump_map,
        pnc: pnc,
    };

    return result;
}

fn analyze_x86(opts: AnalysisOptions) -> Summary {
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
                    let addr = u64::from_str_radix(&l.trim_start_matches("0x"), 16).unwrap();
                    let disas = cs
                        .disasm_count(&opts.binary[(addr - opts.offset) as usize..], addr, 1)
                        .unwrap();

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

                            if !jump_map.contains_key(&addr) {
                                let new_jmp = Jump {
                                    taken: false,
                                    not_taken: false,
                                    condition: String::from(mnemonic.split("j").nth(1).unwrap()),
                                    target: t,
                                    insn_size: insn.bytes().len() as u8,
                                    mode: 0,
                                    pnc: 0,
                                };
                                jump_map.insert(addr, new_jmp);
                            }

                            last_jmp_addr = addr;
                        }
                    }
                }
            }
        }
    }

    let num_uniq_jumps = jump_map.len() as u64;

    let result = Summary {
        time: now.elapsed().as_secs(),
        num_traces: num_traces,
        total_jumps: num_jumps,
        unique_jumps: num_uniq_jumps,
        jumps: jump_map,
        pnc: 0,
    };

    return result;
}

fn analyze_mips(opts: AnalysisOptions) -> Summary {
    println!("[+] Starting Analysis of MIPS Trace");
    let now = Instant::now();

    let cs = Capstone::new()
        .mips()
        .mode(arch::mips::ArchMode::Mips32)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object for MIPS");

    let mut jump_map: HashMap<u64, Jump> = HashMap::new();
    let mut last_jmp_addr: u64 = 0;

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
                    let addr = u64::from_str_radix(&l.trim_start_matches("0x"), 16).unwrap();
                    let disas = cs
                        .disasm_count(&opts.binary[(addr - opts.offset) as usize..], addr, 1)
                        .unwrap();

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
                    };

                    if MIPS_BRANCHES.contains(&insn.id().0) {
                        num_jumps += 1;
                        let mnemonic = insn.mnemonic().unwrap();

                        let t = u64::from_str_radix(
                            insn.op_str().unwrap().split("0x").nth(1).unwrap().trim(),
                            16,
                        )
                        .unwrap();

                        let mut c: &str;
                        if mnemonic.len() < 3 {
                            c = "Z";
                        } else {
                            c = &mnemonic[1..3];
                            if mnemonic.len() > 3
                                && str::to_lowercase(mnemonic).chars().nth(3).unwrap() == 'z'
                            {
                                c = &mnemonic[1..4];
                            }
                        }

                        if !jump_map.contains_key(&addr) {
                            let new_jmp = Jump {
                                taken: false,
                                not_taken: false,
                                condition: String::from(c),
                                target: t,
                                insn_size: insn.bytes().len() as u8,
                                mode: 0,
                                pnc: 0,
                            };
                            jump_map.insert(addr, new_jmp);
                        }

                        last_jmp_addr = addr;
                    }
                }
            }
        }
    }

    let num_uniq_jumps = jump_map.len() as u64;

    let result = Summary {
        time: now.elapsed().as_secs(),
        num_traces: num_traces,
        total_jumps: num_jumps,
        unique_jumps: num_uniq_jumps,
        jumps: jump_map,
        pnc: 0,
    };

    return result;
}

fn main() {
    let options = App::new("JMPscare")
                          .version("0.1")
                          .author("Lukas S. <@pr0me>")
                          .about("Analyze jumps taken across multiple execution traces.")
                          .arg(Arg::with_name("traces")
                               .short("t")
                               .long("traces")
                               .value_name("DIR")
                               .help("Sets path to directory containing collected traces")
                               .required(true)
                               .takes_value(true))
                          .arg(Arg::with_name("output")
                               .short("o")
                               .long("output")
                               .value_name("OUT")
                               .help("Specifies name of output file")
                               .required(false)
                               .takes_value(true))
                          .arg(Arg::with_name("arch")
                               .short("a")
                               .long("arch")
                               .value_name("ARCH")
                               .help("Sets binary target architecture. Supported: x86_64, ARM, MIPS. Default: ARM")
                               .takes_value(true))
                          .arg(Arg::with_name("base")
                               .short("b")
                               .long("base")
                               .value_name("OFFSET")
                               .help("Sets load address offset. I.e. if the address in a trace is 0x8ffff and the offset is 0x10000, the offset into the binary will be 0x7ffff")
                               .takes_value(true))
                          .arg(Arg::with_name("n_jumps")
                               .short("n")
                               .value_name("N")
                               .help("Specifies the amount of edges to traverse (i.e. jumps to take) during Potential New Coverage Analysis")
                               .takes_value(true))
                          .arg(Arg::with_name("weight")
                               .short("w")
                               .value_name("<0-15>")
                               .help("Sets the weight of unresolvable function calls (e.g. 'bl r3') in basic block counting during Potential New Coverage Analysis. Default: 1")
                               .takes_value(true))
                          .arg(Arg::with_name("BINARY")
                               .help("Sets path to original binary the traces were taken from")
                               .required(true)
                               .index(1))
                          .arg(Arg::with_name("skip_warnings")
                               .short("y")
                               .help("Skip all disassembler warnings"))
                          .arg(Arg::with_name("verbose")
                               .short("v")
                               .multiple(true)
                               .help("Show verbose output"))
                          .get_matches();

    let out = options.value_of("output").unwrap_or("jmp_analysis.out");
    let arch = options.value_of("arch").unwrap_or("ARM");
    let base = u64::from_str_radix(
        options
            .value_of("base")
            .unwrap_or("0x00")
            .trim_start_matches("0x"),
        16,
    )
    .expect("Failed to parse base offset");
    let n_jumps = u32::from_str_radix(options.value_of("n_jumps").unwrap_or("3"), 10)
        .expect("Failed to parse number of jumps");
    let weight = u8::from_str_radix(options.value_of("weight").unwrap_or("1"), 10)
        .expect("Failed to parse call weight for basic blocks counting");

    let mut f = File::open(options.value_of("BINARY").unwrap()).expect("Failed to open input file");
    let mut blob = Vec::new();
    f.read_to_end(&mut blob).expect("Failed to read input file");

    let opts = AnalysisOptions {
        binary: blob,
        offset: base,
        trace_path: options.value_of("traces").unwrap(),
        verbosity_lvl: options.occurrences_of("verbose") as u8,
        skip_warnings: options.is_present("skip_warnings"),
        n_jumps: n_jumps.to_owned(),
        call_weight: weight,
    };

    let r: Summary;
    if arch == "ARM" {
        r = analyze_arm(opts);
    } else if arch == "MIPS" {
        r = analyze_mips(opts);
    } else {
        r = analyze_x86(opts);
    }

    generate_output(&r.jumps, out);

    println!(
        "[+] Finished Analysis in {}s
[*] Summary:
    Execution Traces:              {}
    Total conditional Jumps:       {}
    Unique conditional Jumps:      {}
    Uni-directional Jumps:         {}
    Potential New Cov (depth: {:02}): {}",
        r.time,
        r.num_traces,
        r.total_jumps,
        r.unique_jumps,
        &r.jumps.len(),
        n_jumps,
        r.pnc
    );
}
