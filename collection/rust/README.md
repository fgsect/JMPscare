# jxmpscare-col (Rust)

Use the crate by including it in your Cargo.toml:
```
[dependencies]
unicornafl = { path = "/path/to/unicornafl/rust/bindings", version="1.0.0" }
jxmpscare-col = { path = "/path/to/JXMPscare/collection/rust", version="0.1.0"}
```
The crate attempts to write files inside a ./cov/ directory, make sure it exists.
Example usage:
```Rust
use jxmpscare_col::*;

...

let mut unicorn = init_emu_with_heap(Arch::ARM, 1048576*20, 0x90000000, false).expect("failed to create emulator instance");
let mut emu = unicorn.borrow();

...

let f_rc = Rc::new(RefCell::new(vec![]));
let f = f_rc.clone();
let f2 = f_rc.clone();

setup_cov_collection(&mut emu, 0x0, aligned_size, f2);

let crash_validation_callback = move | uc: Unicorn, result: unicornafl::unicorn_const::uc_error, _input: &[u8], _:i32 | {
    write_cov_data::<Heap>(f.borrow().to_vec());
    if result != unicornafl::unicorn_const::uc_error::OK {
        return true;
    }
    return false;
};

...

let ret = emu.afl_fuzz(
    input_file,
    Box::new(place_input_callback),
    &[0x001ff106, 0x001ff0aa],
    Box::new(crash_validation_callback),
    true,
    1
);
```

The example makes use of the unicornafl Rust bindings including a sanitized heap. The bindings can be found here: https://github.com/AFLplusplus/unicornafl/tree/dev/bindings/rust.