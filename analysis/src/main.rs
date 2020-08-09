extern crate clap;
use clap::{Arg, App, SubCommand};
use capstone::prelude::*;
use std::io;
use std::fs::File;
use std::io::Read;
use std::io::BufRead;
use std::fs::{self, DirEntry};
use std::path::Path;

fn read_file(filename: &str) -> Result<String, io::Error> {
    let mut f = File::open(filename)?;
    let mut contents = String::new(); 
    f.read_to_string(&mut contents)?;
    Ok(contents)
}


fn analyze(binary: &Vec<u8>, trace_dir: &str, arch: &str, offset: u32) {
    let mut cs: Capstone;
    let mut cs_t = Capstone::new()
        .arm()
        .mode(arch::arm::ArchMode::Thumb)
        .detail(true)
        .build().expect("failed to create Capstone object for thumb mode");

    if arch == "x86_64" {
        cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).detail(true).build().expect("Failed to create Capstone object for x86_64");
    } else {
        cs = Capstone::new().arm().mode(arch::arm::ArchMode::Arm).detail(true).build().expect("Failed to create Capstone object for ARM");

    }

    for entry in fs::read_dir(trace_dir).expect("Reading directory contents failed") {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() {
            let curr_file = path.to_str().unwrap();
            let fd = File::open(curr_file).expect("Failed to open file");
            for line in io::BufReader::new(fd).lines() {
                if let Ok(l) = line {
                    let mut addr = u64::from_str_radix(&l.trim_start_matches("0x"), 16).unwrap();
                    let mut insn: capstone::Instructions;
                    if addr % 2 == 0 {
                        insn = cs.disasm_count(&binary[addr as usize..], addr, 1).unwrap();
                    } else {
                        addr -= 1;
                        insn = cs_t.disasm_count(&binary[addr as usize..], addr, 1).unwrap();
                    }
                    println!("{}", insn);
                    // TODO: check if curr instruction is conditional jump, create hashmap
                }
            }
        }
    }
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
                          .arg(Arg::with_name("arch")
                               .short("a")
                               .long("arch")
                               .value_name("ARCH")
                               .help("Sets binary target architecture. Supported: x86_64, ARM. Default: x86_64")
                               .takes_value(true))
                          .arg(Arg::with_name("base")
                               .short("b")
                               .long("base")
                               .value_name("OFFSET")
                               .help("Sets base address offset. I.e. if the address in a trace is 0x8ffff and the offset is 0x10000, the offset into the 
                                      binary will be 0x7ffff.")
                               .takes_value(true))
                          .arg(Arg::with_name("BINARY")
                               .help("Sets path to original binary the traces were taken from")
                               .required(true)
                               .index(1))
                          .arg(Arg::with_name("v")
                               .short("v")
                               .help("Show verbose output"))
                          .get_matches();

    let bin_path = options.value_of("BINARY").unwrap();
    let trace_path = options.value_of("traces").unwrap();
    let arch = options.value_of("arch").unwrap_or("x86_64");
    let base = u32::from_str_radix(options.value_of("base").unwrap_or("0x00").trim_start_matches("0x"), 16)
        .expect("Failed to parse base offset.");

    let mut f = File::open(options.value_of("BINARY").unwrap()).expect("Failed to open input file.");
    let mut blob = Vec::new();
    f.read_to_end(&mut blob).expect("Failed to read input file.");

    analyze(&blob, trace_path, arch, base);
    
}