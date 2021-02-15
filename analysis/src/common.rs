use std::{collections::HashMap, fs::File, io::Write};

#[derive(Debug)]
pub struct Jump {
    pub taken: bool,
    pub not_taken: bool,
    pub condition: String,
    pub target: u64,
    pub insn_size: u8,
    pub mode: u8,
    pub pnc: u32,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub entry: u64,
    pub exit: u64,
}

#[derive(Debug)]
pub struct Summary {
    pub time: u64,
    pub num_traces: u64,
    pub total_jumps: u64,
    pub unique_jumps: u64,
    pub jumps: HashMap<u64, Jump>,
    pub pnc: u32,
}

#[derive(Debug)]
pub struct AnalysisOptions<'a> {
    pub binary: Vec<u8>,
    pub offset: u64,
    pub trace_path: &'a str,
    pub verbosity_lvl: u8,
    pub skip_warnings: bool,
    pub n_jumps: u32,
    pub call_weight: u8,
}

// write analysis report to file, to be parsed by JMPscare disassembler plugins
pub fn generate_output(jumps: &HashMap<u64, Jump>, file_name: &str) {
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
pub fn find_ud_jumps(jumps: &mut HashMap<u64, Jump>) {
    jumps.retain(|_k, v| v.taken != v.not_taken)
}

// reduce noise (check if basic block behind uni-directional jump has coverage)
pub fn check_bb_cov(jumps: &mut HashMap<u64, Jump>, blocks: &HashMap<u64, BasicBlock>) {
    jumps.retain(|k, v| {
        let not_visited = if v.taken {
            *k + v.insn_size as u64
        } else {
            v.target
        };
        !blocks.contains_key(&not_visited)
    })
}
