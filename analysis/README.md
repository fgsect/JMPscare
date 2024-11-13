# Analysis Tool

This command line tool takes execution traces and the path to a binary in order to analyze which jumps were taken and which parts of a program are never reached.
Furthermore, the number of unseen basic blocks reachable in N (user specified) edge traversals behind a roadblock branch can be evaluated for ARM binaries.
At the moment, the ARM (incl. thumb2), x86_64 and MIPS32 architectures are supported.

## Building & Running

The program is written in Rust and can be conveniently built with cargo. Make sure to compile in release mode, as this will yield significant speedups for large amounts of input files:

```sh
cargo build --release
```

As parameters, at least the path to the original binary and a directory with input traces are expected:

```sh
./target/release/jmpscare ./example_binary -t ./cov
```

For further information, please use `--help`.

## Input File Formatting

JMPscare analysis works on simple execution trace files with one address per line. Please note, that for instructions in thumb mode, the LSB is expected to be 1.
The generation of such files can be achieved e.g. by using the provided collection modules with the Unicorn emulator.

## Output File Formatting

The tool will generate a single output file, offering details about all uni-directional jumps, i.e. conditional jumps or branches which are always/never taken across all execution traces.
Every line describes one such jump, specifying the address in the binary, the jump's condition, whether it is taken always or never and the potential new coverage behind this jump (i.e., number of unseen basic blocks reachable in _N_ jumps).

E.g.:

```sh
0x1337 CONDITION_LT NEVER_TAKEN 7
```

Generated analysis summaries can further be used with the disassembler plugins coming with this repository.
