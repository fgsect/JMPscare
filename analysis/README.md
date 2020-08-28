# Analysis Tool

This command line tool takes execution traces and the path to a binary in order to analyze which jumps were taken and which parts of a program are never reached. 
At the moment, the x86_64 and ARM (incl. thumb2) architectures are supported.

## Building & Running
The program is written in Rust and can be conveniently built with cargo. Make sure to compile in release mode, as this will yield significant speedups for large amounts of input files:

```
cargo build --release
```
As parameters, at least the path to the original binary and a directory with input traces are expected:
```
./target/release/jxmpscare ./example_binary -t ./cov
```
For further information, please use ```--help```.

## Inpute File Formatting
JXMPscare analysis works on simple execution trace files with one address per line. Please note, that for instructions in thumb mode, the LSB is expected to be 1.
The generation of such files can be achieved e.g. by using the provided collection modules.

## Output File Formatting
The tool will generate a single output file, offering details about all uni-directional jumps, i.e. conditional jumps or branches which are always/never taken across all execution traces.
Every line describes one such jump, specifying the address in the binary, the jump's condition and whether it is taken always or never. E.g.:
```
0x1172 CONDITION_LT NEVER_TAKEN
```

Generated analysis outputs can further be used with the disassembler plugins coming with this repository.