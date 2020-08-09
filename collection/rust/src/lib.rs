use unicornafl::unicorn_const::{uc_error, Mode, Arch};
use unicornafl::RegisterARM;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::cell::RefCell;
use std::cell::RefMut;
use std::rc::Rc;
use std::rc::Weak;
use std::fs::File;
use std::io::prelude::*;


/// Add code hooks and callbacks to collect coverage data.
/// 
/// Call this before 'uc_afl_fuzz' or alike.
/// Performance was never an option.
pub fn setup_cov_collection<D>(uc: &mut unicornafl::UnicornHandle<D>, code_start: u64, code_end: u64, cov_data: Rc<RefCell<Vec<u64>>>) {
    
    let callback = Box::new(move |uc: unicornafl::UnicornHandle<D>, addr: u64, size: u32| {
        let mut tuples = cov_data.borrow_mut();

        if (uc.get_arch() == Arch::ARM || uc.get_arch() == Arch::ARM64) && 
            uc.reg_read(RegisterARM::CPSR as i32).expect("failed to read CPSR") & 0x20 != 0 {
            tuples.push(addr + 1);
        } else {
            tuples.push(addr);
        }

    });

    uc.add_code_hook(code_start, code_end, callback).expect("Failed to add coverage collection hook");
}


/// Write coverage data to disk.
/// 
/// Make sure to call this after each fuzz run, i.e. set always_validate to true
/// in 'uc_afl_fuzz' and call this function inside the crash validation callback. 
pub fn write_cov_data<D>(trace: Vec<u64>) -> std::io::Result<()> {

    let mut s = DefaultHasher::new();
    trace.hash(&mut s);
    let x = s.finish();
    let mut file = File::create("./cov/".to_string() + &x.to_string())?;

    for addr in trace {
        file.write(format!("0x{:x}\n", addr).as_bytes())?;
    }

    Ok(())
}