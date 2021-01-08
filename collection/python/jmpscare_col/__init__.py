from unicornafl import *
import zlib


def setup_cov_collection(uc, code_start, code_end, cov_data):
    def callback(uc, address, size, user_data=None):
        cov_data.append(address)
    
    uc.hook_add(UC_HOOK_CODE, callback, None, code_start, code_end)


def write_cov_data(trace):
    h = zlib.adler32(str(trace).encode())
    with open("./cov/" + str(h), 'w+') as f:
        for addr in trace:
            f.write(hex(addr) + '\n')

    return True