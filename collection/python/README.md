# jmpscare-col (Python)

Install with 
```
pip install --user -e ./
```
The module attempts to write files inside a ./cov/ directory, make sure it exists.
Example usage:
```Python
from unicornafl import *
from unicornafl.x86_const import *
from jmpscare_col import *

traces = []

def crash_cb(uc, result, curr_input, curr_round, data):
    write_cov_data(traces)
    if result != UC_ERR_OK:
        return True
    return False

...

uc = Uc(UC_ARCH_X86, UC_MODE_64)
setup_cov_collection(uc, 0x1119, 0x11ca, traces)

...

uc.afl_fuzz(input_file,             
            place_input_callback,   # type: Callable[[Uc, bytes, int, Any], Optional[bool]]
            [0x11ca],
            validate_crash_callback=crash_cb,
            always_validate=True,
            persistent_iters=1,
            data=None,
    )
```

The example makes use of the unicornafl Python bindings. The bindings can be found here: https://github.com/AFLplusplus/unicornafl/tree/dev/bindings/python.