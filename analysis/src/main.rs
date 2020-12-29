extern crate clap;
use clap::{Arg, App};
use capstone::prelude::*;
use std::io;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::Read;
use std::io::BufRead;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Debug)]
pub struct Jump {
    taken: bool,
    not_taken: bool,
    condition: String,
    target: u64,
    insn_size: u8,
}

#[derive(Debug)]
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
}

#[derive(Debug)]
pub struct AnalysisOptions {
    offset: u64,
    verbosity_lvl: u8,
    skip_warnings: bool,
}


const MIPS_BRANCHES: [u32; 46] = [
    arch::mips::MipsInsn::MIPS_INS_BEQ as u32,
    arch::mips::MipsInsn::MIPS_INS_BEQC as u32,
    arch::mips::MipsInsn::MIPS_INS_BEQL as u32,
    arch::mips::MipsInsn::MIPS_INS_BEQZ16 as u32 ,
    arch::mips::MipsInsn::MIPS_INS_BEQZALC as u32,
    arch::mips::MipsInsn::MIPS_INS_BEQZC as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEC as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEUC as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEZ as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEZAL as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEZALC as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEZALL as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEZALS as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEZC as u32,
    arch::mips::MipsInsn::MIPS_INS_BGEZL as u32,
    arch::mips::MipsInsn::MIPS_INS_BGTZ as u32,
    arch::mips::MipsInsn::MIPS_INS_BGTZALC as u32,
    arch::mips::MipsInsn::MIPS_INS_BGTZC as u32,
    arch::mips::MipsInsn::MIPS_INS_BGTZL as u32,
    arch::mips::MipsInsn::MIPS_INS_BLEZ as u32,
    arch::mips::MipsInsn::MIPS_INS_BLEZALC as u32,
    arch::mips::MipsInsn::MIPS_INS_BLEZC as u32,
    arch::mips::MipsInsn::MIPS_INS_BLEZL as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTC as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTUC as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTZ as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTZAL as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTZALC as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTZALL as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTZALS as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTZC as u32,
    arch::mips::MipsInsn::MIPS_INS_BLTZL as u32,
    arch::mips::MipsInsn::MIPS_INS_BNE as u32,
    arch::mips::MipsInsn::MIPS_INS_BNEC as u32,
    arch::mips::MipsInsn::MIPS_INS_BNEGI as u32,
    arch::mips::MipsInsn::MIPS_INS_BNEG as u32,
    arch::mips::MipsInsn::MIPS_INS_BNEL as u32,
    arch::mips::MipsInsn::MIPS_INS_BNEZ16 as u32,
    arch::mips::MipsInsn::MIPS_INS_BNEZALC as u32,
    arch::mips::MipsInsn::MIPS_INS_BNEZC as u32,
    arch::mips::MipsInsn::MIPS_INS_BNVC as u32,
    arch::mips::MipsInsn::MIPS_INS_BOVC as u32,
    arch::mips::MipsInsn::MIPS_INS_BNZ as u32,
    arch::mips::MipsInsn::MIPS_INS_BZ as u32,
    arch::mips::MipsInsn::MIPS_INS_BEQZ as u32,
    arch::mips::MipsInsn::MIPS_INS_BNE as u32
];

// write analysis report to file, to be parsed by JXMPscare disassembler plugins
fn generate_output(map: &HashMap<u64, Jump>, file_name: &str) {
    println!("    Generating Output File");
    let mut file = File::create(file_name.to_string()).expect("Failed to create file");
    for (k, v) in map.iter() {
        let s = if v.taken { "ALWAYS_TAKEN" } else { "NEVER_TAKEN" };
        let line = format!("{:#X} CONDITION_{} {}\n", k, v.condition.to_uppercase(), s);
        file.write(line.as_bytes()).expect("Failed to write to file");
    }
}


fn find_ud_jumps(jumps: &mut HashMap<u64, Jump>) {
    jumps.retain(|_k, v| {
        v.taken != v.not_taken
    })
}


// reduce noise (check if basic block behind uni-directional jump has coverage)
fn check_bb_cov(jumps: &mut HashMap<u64, Jump>, blocks: &HashMap<u64, BasicBlock>) {
    jumps.retain(|k, v| {
        let not_visited = if v.taken { *k + v.insn_size as u64 } else { v.target };
        !blocks.contains_key(&not_visited)
    })
}


fn analyze_arm(binary: &Vec<u8>, trace_dir: &str, opts: AnalysisOptions) -> Summary {
    println!("[+] Starting analysis of ARM trace");
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
        .expect("failed to create Capstone object for thumb mode");

    let mut jump_map: HashMap<u64, Jump> = HashMap::new();
    let mut bb_bucket: HashMap<u64, BasicBlock> = HashMap::new();
    let mut last_jmp_addr: u64 = 0;
    let mut curr_bb: u64 = 0;


    let mut num_traces = 0;
    let mut num_jumps = 0;
    let mut ignore_list = HashSet::new();

    println!("    Parsing Execution Traces");

    // parse execution traces
    for entry in fs::read_dir(trace_dir).expect("Reading directory contents failed") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            let curr_file = path.to_str().unwrap();
            let fd = File::open(curr_file).expect("Failed to open file");
            num_traces += 1;

            for line in io::BufReader::new(fd).lines() {
                if let Ok(l) = line {
                    let mut addr = u64::from_str_radix(&l.trim_start_matches("0x"), 16).unwrap();

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
                        disas = cs.disasm_count(&binary[(addr - opts.offset) as usize..], addr, 1).unwrap();
                    } else {
                        // Requirement: trace addresses of instructions in thumb mode have the LSB set to 1
                        addr -= 1;
                        disas = cs_t.disasm_count(&binary[(addr - opts.offset) as usize..], addr, 1).unwrap();
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
                                    std::io::stdin().read_line(&mut input).expect("failed to read user input");
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

                    if insn.id() == capstone::InsnId(17) { // branch
                        num_jumps += 1;
                        let mnemonic = insn.mnemonic().unwrap();

                        // conditional branch
                        if mnemonic.len() > 2 && mnemonic != "blx" && &mnemonic[1..2] != "." {
                            let t = u64::from_str_radix(&disas
                                .to_string()
                                .split("#0x")
                                .nth(1).unwrap()
                                .trim(), 16).unwrap();
                            
                            if !jump_map.contains_key(&addr) {
                                let new_jmp = Jump {
                                    taken: false, 
                                    not_taken: false, 
                                    condition: String::from(&mnemonic[1..3]), 
                                    target: t,
                                    insn_size: insn.bytes().len() as u8
                                };
                                jump_map.insert(addr, new_jmp);
                            }

                            last_jmp_addr = addr;
                        }
                        
                    }
                    
                    // close basic block on jump
                    if insn.id() >= capstone::InsnId(13) && insn.id() <= capstone::InsnId(17) || // BL, BX, BXL, BXJ, B
                       insn.id() >= capstone::InsnId(421) && insn.id() <= capstone::InsnId(423) { // CBNZ, CBZ, POP
                        let new_bb = BasicBlock {
                            entry: curr_bb,
                            exit: addr
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
    
    let result = Summary {
        time: now.elapsed().as_secs(),
        num_traces: num_traces, 
        total_jumps: num_jumps,
        unique_jumps: num_uniq_jumps,
        jumps: jump_map,
    };

    return result;
}


fn analyze_x86(binary: &Vec<u8>, trace_dir: &str, opts: AnalysisOptions) -> Summary {
    println!("[+] Starting analysis of x86_64 trace");
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

    println!("    Parsing Execution Traces");

    // parse execution traces
    for entry in fs::read_dir(trace_dir).expect("Reading directory contents failed") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            let curr_file = path.to_str().unwrap();
            let fd = File::open(curr_file).expect("Failed to open file");
            num_traces += 1;

            for line in io::BufReader::new(fd).lines() {
                if let Ok(l) = line {
                    let addr = u64::from_str_radix(&l.trim_start_matches("0x"), 16).unwrap();
                    let disas = cs.disasm_count(&binary[(addr - opts.offset) as usize..], addr, 1).unwrap();
                    
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
                                std::io::stdin().read_line(&mut input).expect("failed to read user input");
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
                    
                    if insn.id().0 >= 253 && insn.id().0 <= 270  { // branch
                        num_jumps += 1;
                        let mnemonic = insn.mnemonic().unwrap();

                        // conditional branch
                        if mnemonic != "jmp" {
                            let t = u64::from_str_radix(insn.op_str().unwrap()
                                .split("0x")
                                .nth(1).unwrap()
                                .trim(), 16).unwrap();
                            
                            if !jump_map.contains_key(&addr) {
                                let new_jmp = Jump {
                                    taken: false, 
                                    not_taken: false, 
                                    condition: String::from(mnemonic.split("j").nth(1).unwrap()), 
                                    target: t,
                                    insn_size: insn.bytes().len() as u8
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
    };

    return result;
}


fn analyze_mips(binary: &Vec<u8>, trace_dir: &str, opts: AnalysisOptions) -> Summary {
    println!("[+] Starting analysis of MIPS trace");
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

    println!("    Parsing Execution Traces");

    // parse execution traces
    for entry in fs::read_dir(trace_dir).expect("Reading directory contents failed") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            let curr_file = path.to_str().unwrap();
            let fd = File::open(curr_file).expect("Failed to open file");
            num_traces += 1;

            for line in io::BufReader::new(fd).lines() {
                if let Ok(l) = line {
                    let addr = u64::from_str_radix(&l.trim_start_matches("0x"), 16).unwrap();
                    let disas = cs.disasm_count(&binary[(addr - opts.offset) as usize..], addr, 1).unwrap();

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
                                std::io::stdin().read_line(&mut input).expect("failed to read user input");
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

                        let t = u64::from_str_radix(insn.op_str().unwrap()
                            .split("0x")
                            .nth(1).unwrap()
                            .trim(), 16).unwrap();

                        let mut c: &str;
                        if mnemonic.len() < 3 {
                            c = "Z";
                        } else {
                            c = &mnemonic[1..3];
                            if mnemonic.len() > 3 && str::to_lowercase(mnemonic).chars().nth(3).unwrap() == 'z' {
                                c = &mnemonic[1..4];
                            }
                        }

                        if !jump_map.contains_key(&addr) {
                            let new_jmp = Jump {
                                taken: false,
                                not_taken: false,
                                condition: String::from(c),
                                target: t,
                                insn_size: insn.bytes().len() as u8
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
    };

    return result;
}


fn main() {
    let options = App::new("JXMPscare")
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
                               .help("Sets binary target architecture. Supported: x86_64, ARM, MIPS. Default: x86_64")
                               .takes_value(true))
                          .arg(Arg::with_name("base")
                               .short("b")
                               .long("base")
                               .value_name("OFFSET")
                               .help("Sets load address offset. I.e. if the address in a trace is 0x8ffff and the offset is 0x10000, the offset into the binary will be 0x7ffff")
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

    let trace_path = options.value_of("traces").unwrap();
    let out = options.value_of("output").unwrap_or("jxmp_analysis.out");
    let arch = options.value_of("arch").unwrap_or("x86_64");
    let base = u64::from_str_radix(options.value_of("base").unwrap_or("0x00").trim_start_matches("0x"), 16)
        .expect("Failed to parse base offset");

    let opts = AnalysisOptions {
        offset: base,
        verbosity_lvl: options.occurrences_of("verbose") as u8,
        skip_warnings: options.is_present("skip_warnings")
    };

    let mut f = File::open(options.value_of("BINARY").unwrap()).expect("Failed to open input file");
    let mut blob = Vec::new();
    f.read_to_end(&mut blob).expect("Failed to read input file");

    let r: Summary;
    if arch == "ARM" {
        r = analyze_arm(&blob, trace_path, opts);
    } else if arch == "MIPS" {
        r = analyze_mips(&blob, trace_path, opts);
    } else {
        r = analyze_x86(&blob, trace_path, opts);
    }

    generate_output(&r.jumps, out);
    
    println!("[-] Finished Analysis in {}s
[*] Summary:
    Execution Traces:         {}
    Total conditional Jumps:  {}
    Unique conditional Jumps: {}
    Uni-directional Jumps:    {}", r.time, r.num_traces, r.total_jumps, r.unique_jumps, &r.jumps.len());
    
}