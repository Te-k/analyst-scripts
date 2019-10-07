#!/usr/bin/env python3
import argparse
from capstone import *

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Disassemble')
    parser.add_argument('--type', '-t', choices=['x86', 'x86-64', 'ARM', 'ARM64'],
                    help='Type of architecture')
    parser.add_argument('FILE', help='binary file')
    args = parser.parse_args()

    with open(args.FILE, 'rb') as f:
        code = f.read()

    if args.type == 'x86':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif args.type == 'x86-64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif args.type == 'ARM':
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    else:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    for (address, size, mnemonic, op_str) in md.disasm_lite(code, 0x1000):
        print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
