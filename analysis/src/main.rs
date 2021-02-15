extern crate clap;

mod arm;
pub mod common;
mod mips;
mod x86;

use clap::{App, Arg};
use std::{fs::File, io::Read};

use crate::{
    arm::analyze_arm,
    common::{generate_output, AnalysisOptions, Summary},
    mips::analyze_mips,
    x86::analyze_x86,
};

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
