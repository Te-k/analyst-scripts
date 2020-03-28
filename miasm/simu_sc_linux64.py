from argparse import ArgumentParser
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_SYSCALL
from miasm.analysis.machine import Machine
from pdb import pm

SOCKETCALL = {
        1: "SYS_SOCKET",
        2: "SYS_BIND",
        3: "SYS_CONNECT",
        4: "SYS_LISTEN",
        5: "SYS_ACCEPT",
        6: "SYS_GETSOCKNAME",
        7: "SYS_GETPEERNAME",
        8: "SYS_SOCKETPAIR",
        9: "SYS_SEND",
        10: "SYS_RECV",
        11: "SYS_SENDTO",
        12: "SYS_RECVFROM",
        13: "SYS_SHUTDOWN",
        14: "SYS_SETSOCKOPT",
        15: "SYS_GETSOCKOPT",
        16: "SYS_SENDMSG",
        17: "SYS_RECVMSG",
        18: "SYS_ACCEPT4",
        19: "SYS_RECVMMSG",
        20: "SYS_SENDMMSG"
    }


def get_str(jit, addr):
    data = jit.vm.get_mem(addr, 10)
    return data[:data.find(b'\x00')].decode('utf-8')


def exception_int(jitter):
    print("SYSCALL {}".format(jitter.cpu.EAX))
    jitter.cpu.set_exception(0)
    return True

if __name__ == '__main__':
    parser = ArgumentParser(description="x86 64 basic Jitter")
    parser.add_argument("filename", help="x86 64 shellcode filename")
    parser.add_argument("-j", "--jitter",
                        help="Jitter engine",
                        default="python")
    args = parser.parse_args()

    myjit = Machine("x86_64").jitter(args.jitter)
    myjit.init_stack()

    data = open(args.filename, 'rb').read()
    run_addr = 0x40000000
    myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)
    #myjit.set_trace_log()
    myjit.add_exception_handler(EXCEPT_SYSCALL, exception_int)
    myjit.run(run_addr)
