//! Analysis functions and structs used in all platforms
use std::{collections::HashMap, fs::File, hash::BuildHasher, io::Write, time::Duration};

/// Describing a single Jump
#[derive(Debug)]
pub struct Jump {
    /// True, if this jump was taken
    pub taken: bool,
    /// True, if this jump was taken
    pub not_taken: bool,
    /// A readable representation of this jump was taken
    pub condition: String,
    /// The target address of this jump
    pub target: u64,
    /// The instruction size
    pub insn_size: u8,
    /// The mode size
    pub mode: u8,
    /// the `potential new coverage`-value
    pub pnc: u32,
}

/// A block of code
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Entry address
    pub entry: u64,
    /// Exit address
    pub exit: u64,
}

/// Summary of the analysis
#[derive(Debug)]
pub struct Summary {
    /// Time this analysis took
    pub time: Duration,
    /// Amount of traces we worked on
    pub num_traces: u64,
    /// The total jumps analyzed
    pub total_jumps: u64,
    /// Unique Jumps encountered
    pub unique_jumps: u64,
    /// List of all jumps
    pub jumps: HashMap<u64, Jump>,
    /// The total `potential new coverage`-value
    pub pnc: u32,
}

/// Options passed to the analysis
#[derive(Debug)]
pub struct AnalysisOptions {
    pub binary: Vec<u8>,
    pub offset: u64,
    /// Forces thumb mode for ARM firmware
    pub force_thumb: bool,
    pub trace_path: String,
    pub verbosity_lvl: u8,
    pub skip_warnings: bool,
    pub n_jumps: u32,
    pub call_weight: u8,
}

/// write analysis report to file, to be parsed by `JMPscare` disassembler plugins
///
/// # Panics
/// panics if report file could not be written to for a number of reasons
pub fn generate_output<H: BuildHasher>(jumps: &HashMap<u64, Jump, H>, file_name: &str) {
    println!(" >  Generating Output File");
    let mut file = File::create(file_name).expect("Failed to create file");
    for (k, v) in jumps {
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
        file.write_all(line.as_bytes())
            .expect("Failed to write to file");
    }
}

/// filter for uni-directional jumps
pub fn find_ud_jumps<H: BuildHasher>(jumps: &mut HashMap<u64, Jump, H>) {
    jumps.retain(|_k, v| v.taken != v.not_taken);
}

/// reduce noise (check if basic block behind uni-directional jump has coverage)
pub fn check_bb_cov<H: BuildHasher>(
    jumps: &mut HashMap<u64, Jump, H>,
    blocks: &HashMap<u64, BasicBlock, H>,
) {
    jumps.retain(|k, v| {
        let not_visited = if v.taken {
            *k + u64::from(v.insn_size)
        } else {
            v.target
        };
        !blocks.contains_key(&not_visited)
    });
}
