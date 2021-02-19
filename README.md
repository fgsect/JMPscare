# JMPscare
Toolkit for multi-execution jump coverage introspection: Analyze your fuzzing results by inspecting which conditional jumps you are missing.

This repository includes the following components:
* Collection
    * [Rust](./collection/rust/README.md) and [Python 3](./collection/python/README.md) modules to easily collect execution traces with [unicornafl](https://github.com/AFLplusplus/unicornafl)
* [Analysis](./analysis/README.md)
    * tool to analyze multiple execution traces in order to **find conditional jumps which are always/never taken**
    * works on any simple execution trace (file with one address per line)
    * supports ARM32, x86_64 and MIPS32
    * **Potential New Coverage Analysis** (ARM-only for now): Evaluate the number of new basic blocks behind a uni-directional jump, reachable in _N_ branches
* Plugins
    * [Binary Ninja plugin](./plugins/binaryninja/jmpscare/README.md) to visualize analysis results
        * concise overview of roadblock jumps
        * instruction highlighting
        * easy navigation and auto-patching (invert branch conditions for _forced execution_)
    * Ghidra plugin WIP

For further information, please confer to the READMEs within each directory.

![JMPscare Binary Ninja Screenshot](./binja.png "Binary Ninja Plugin")

For further information, refer to our paper at BAR 2021, "JMPscare: Introspection for Binary-Only Fuzzing"