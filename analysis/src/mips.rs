//! The analyses for MIPS
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fs::{self, File},
    io::{self, BufRead},
    time::Instant,
};

use capstone::{arch::mips::MipsInsn, prelude::*};

use crate::common::{AnalysisOptions, Jump, Summary};

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

/// The arm `JMPscare` analysis
#[allow(clippy::too_many_lines)]
pub fn analyze_mips(opts: &AnalysisOptions) -> Summary {
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

            for l in io::BufReader::new(fd).lines().map_while(Result::ok) {
                let addr = u64::from_str_radix(l.trim_start_matches("0x"), 16).unwrap();
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

                    jump_map.entry(addr).or_insert_with(|| {
                        let new_jmp = Jump {
                            taken: false,
                            not_taken: false,
                            condition: String::from(c),
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
