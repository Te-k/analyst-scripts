#!/usr/bin/python
import argparse
import pefile
import os
import sys


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract PE Signature')
    parser.add_argument('PEFILE', help='PE File')
    parser.add_argument('--output', '-o', help='Output file')
    args = parser.parse_args()

    if not os.path.isfile(args.PEFILE):
        print("Invalid path")
        sys.exit(-1)

    if args.output:
        output = args.output
    else:
        output = args.PEFILE + '.sig'

    pe =  pefile.PE(args.PEFILE)

    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    if address == 0:
        print('Source file not signed')
        sys.exit(0)

    signature = pe.write()[address+8:]
    f = open(output, 'wb+')
    f.write(signature)
    f.close()
