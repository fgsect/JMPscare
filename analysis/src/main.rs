//!`JMPscare`, the main
extern crate clap;

mod arm;
pub mod common;
mod mips;
mod x86;

use std::{fs::File, io::Read};

use clap::{Arg, ArgAction, Command};

use crate::{
    arm::analyze_arm,
    common::{generate_output, AnalysisOptions, Summary},
    mips::analyze_mips,
    x86::analyze_x86,
};

#[allow(clippy::too_many_lines)]
fn main() {
    let options = Command::new("JMPscare")
                          .version("0.1")
                          .author("Lukas S. <@pr0me>")
                          .about("Analyze jumps taken across multiple execution traces.")
                          .arg(Arg::new("traces")
                               .short('t')
                               .long("traces")
                               .value_name("DIR")
                               .help("Sets path to directory containing collected traces")
                               .required(true))
                          .arg(Arg::new("output")
                               .short('o')
                               .long("output")
                               .value_name("OUT")
                               .help("Specifies name of output file")
                               .required(false))
                          .arg(Arg::new("arch")
                               .short('a')
                               .long("arch")
                               .value_name("ARCH")
                               .help("Sets binary target architecture. Supported: x86_64, ARM, MIPS. Default: ARM")
)
                          .arg(Arg::new("base")
                               .short('b')
                               .long("base")
                               .value_name("OFFSET")
                               .help("Sets load address offset. I.e. if the address in a trace is 0x8ffff and the offset is 0x10000, the offset into the binary will be 0x7ffff")
)
                          .arg(Arg::new("n_jumps")
                               .short('n')
                               .value_name("N")
                               .help("Specifies the amount of edges to traverse (i.e. jumps to take) during Potential New Coverage Analysis")
)
                          .arg(Arg::new("weight")
                               .short('w')
                               .value_name("<0-15>")
                               .help("Sets the weight of unresolvable function calls (e.g. 'bl r3') in basic block counting during Potential New Coverage Analysis. Default: 1")
)
                          .arg(Arg::new("BINARY")
                               .help("Sets path to original binary the traces were taken from")
                               .required(true)
                               .index(1))
                          .arg(Arg::new("skip_warnings")
                               .short('y')
                               .action(ArgAction::SetTrue)
                               .help("Skip all disassembler warnings"))
                          .arg(Arg::new("verbose")
                               .short('v')
                               .action(ArgAction::Count)
                               .help("Show verbose output"))
                          .arg(Arg::new("force_thumb")
                                .long("force_thumb")
                                .short('f')
                                .action(ArgAction::SetTrue)
                                .help("For arm32: Forces decoding in thumb mode, even if the addresses don't have the thumb-bit set."))
                          .get_matches();

    let default_output = "jmp_analysis.out".to_string();
    let out = options
        .get_one::<String>("output")
        .unwrap_or(&default_output);
    let default_arch = "ARM".to_string();
    let arch = options.get_one::<String>("arch").unwrap_or(&default_arch);
    let force_thumb = options.get_flag("force_thumb");

    assert!(
        !force_thumb || arch == "ARM",
        "The force_thumb flags was provided for non-arm architecture: {arch}"
    );

    let base = u64::from_str_radix(
        options
            .get_one::<String>("base")
            .unwrap_or(&"0x00".to_string())
            .trim_start_matches("0x"),
        16,
    )
    .expect("Failed to parse base offset");
    let n_jumps = options
        .get_one::<String>("n_jumps")
        .unwrap_or(&"3".to_string())
        .parse::<u32>()
        .expect("Failed to parse number of jumps");
    let weight = options
        .get_one::<String>("weight")
        .unwrap_or(&"1".to_string())
        .parse::<u8>()
        .expect("Failed to parse call weight for basic blocks counting");

    let mut f = File::open(options.get_one::<String>("BINARY").unwrap())
        .expect("Failed to open input file");
    let mut blob = Vec::new();
    f.read_to_end(&mut blob).expect("Failed to read input file");

    let opts = AnalysisOptions {
        binary: blob,
        force_thumb,
        offset: base,
        trace_path: options.get_one::<String>("traces").unwrap().clone(),
        verbosity_lvl: options.get_count("verbose"),
        skip_warnings: options.get_flag("skip_warnings"),
        n_jumps: n_jumps.to_owned(),
        call_weight: weight,
    };

    let r: Summary;
    if arch == "ARM" {
        r = analyze_arm(&opts);
    } else if arch == "MIPS" {
        r = analyze_mips(&opts);
    } else {
        r = analyze_x86(&opts);
    }

    generate_output(&r.jumps, out);

    println!(
        "[*] File written to {out}
[+] Finished Analysis in {}s
[*] Summary:
    Execution Traces:              {}
    Total conditional Jumps:       {}
    Unique conditional Jumps:      {}
    Uni-directional Jumps:         {}
    Potential New Cov (depth: {:02}): {}",
        r.time.as_secs(),
        r.num_traces,
        r.total_jumps,
        r.unique_jumps,
        &r.jumps.len(),
        n_jumps,
        r.pnc
    );
}
