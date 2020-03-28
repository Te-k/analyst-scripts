from argparse import ArgumentParser
from pdb import pm
import struct
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_INT_XX, EXCEPT_ACCESS_VIOL, EXCEPT_PRIV_INSN
from miasm.analysis.machine import Machine

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

SOCKET_DOMAINS = {
    1: "AF_UNIX",
    2: "AF_INET"
}

SOCKET_TYPE = {
    1: "SOCK_STREAM",
    2: "SOCK_DGRAM",
    3: "SOCK_RAW"
}

SYSCALL = {
    3: "READ",
    125: "mprotect"
}


def get_str(jit, addr):
    data = jit.vm.get_mem(addr, 10)
    return data[:data.find(b'\x00')].decode('utf-8')


def exception_int(jitter):
    if jitter.cpu.EAX == 11:
        # sys_execve
        pathname = get_str(jitter, jitter.cpu.EBX)
        argv = []
        i = 0
        arg_addr = jitter.vm.get_u32(jitter.cpu.ECX)
        while arg_addr != 0:
            argv.append(get_str(jitter, arg_addr))
            i += 4
            arg_addr = jitter.vm.get_u32(jitter.cpu.ECX+i)
        envp = jitter.cpu.EDX
        print("execve({}, {}, {})".format(
            pathname,
            str(argv),
            envp
        ))
    elif jitter.cpu.EAX == 102:
        if jitter.cpu.EBX == 1:
            domain = jitter.vm.get_u32(myjit.cpu.ESP)
            stype = jitter.vm.get_u32(myjit.cpu.ESP+4)
            proto = jitter.vm.get_u32(myjit.cpu.ESP+8)
            print('socket({} {}, {} {}, {})'.format(
                SOCKET_DOMAINS[domain],
                domain,
                SOCKET_TYPE[stype],
                stype,
                proto
            ))
            jitter.cpu.EAX = 14
        elif jitter.cpu.EBX == 2:
            print('BIND')
            jitter.cpu.EAX = 3
        elif jitter.cpu.EBX == 3:
            # Connect
            sockfd = jitter.vm.get_u32(myjit.cpu.ESP)
            addr_len = jitter.vm.get_u32(myjit.cpu.ESP+8)
            addr = jitter.vm.get_mem(jitter.vm.get_u32(myjit.cpu.ESP+4), 8)
            print("connect({}, [{}, {}, {}], {})".format(
                sockfd,
                struct.unpack("H", addr[0:2])[0],
                struct.unpack(">H", addr[2:4])[0],
                ".".join([str(i) for i in struct.unpack("BBBB", addr[4:8])]),
                addr_len
            ))
        else:
            if jitter.cpu.EBX in SOCKETCALL:
                print(SOCKETCALL[jitter.cpu.EBX])
            else:
                print("unknown socketcall")
    else:
        if jitter.cpu.EAX in SYSCALL.keys():
            print("{}".format(SYSCALL[jitter.cpu.EAX]))
        else:
            print("Unknown syscall {}".format(jitter.cpu.EAX))
    jitter.cpu.set_exception(0)
    return True


def code_sentinelle(jitter):
    print("Done")
    jitter.run = False
    jitter.pc = 0
    return True

def priv(jitter):
    print("Privilege Exception")
    return False


if __name__ == '__main__':
    parser = ArgumentParser(description="x86 32 basic Jitter")
    parser.add_argument("filename", help="x86 32 shellcode filename")
    parser.add_argument("-j", "--jitter",
                        help="Jitter engine",
                        default="python")
    parser.add_argument("--verbose", "-v", action="store_true",
            help="Verbose mode")
    args = parser.parse_args()

    myjit = Machine("x86_32").jitter(args.jitter)
    myjit.init_stack()

    data = open(args.filename, 'rb').read()
    run_addr = 0x40000000
    myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)
    if args.verbose:
        myjit.set_trace_log()
    myjit.add_exception_handler(EXCEPT_INT_XX, exception_int)
    myjit.add_exception_handler(EXCEPT_PRIV_INSN, priv)
    myjit.push_uint32_t(0x1337beef)
    myjit.add_exception_handler(EXCEPT_ACCESS_VIOL, code_sentinelle)
    myjit.add_breakpoint(0x1337beef, code_sentinelle)
    myjit.run(run_addr)
