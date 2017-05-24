#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import pefile
import argparse
import sys
import hashlib
import datetime

"""Search a string in a PE file
Author : Tek <tek@randhome.io>
Date : 05/24/2017
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Search string in a PE file')
    parser.add_argument('STRING', help='a string')
    parser.add_argument('FILE', help='a PE file')
    args = parser.parse_args()

    fin = open(args.FILE, 'rb')
    data = fin.read()
    fin.close()

    # Search for physical location
    pos = data.find(args.STRING)
    if pos == -1:
        print("String not found...")
        sys.exit(1)

    print('Position in the file : 0x%x' % pos)

    # Search position in the PE
    pe = pefile.PE(data=data)
    # Check in sections first
    for s in pe.sections:
        if (pos >= s.PointerToRawData) and (pos <= s.PointerToRawData + s.SizeOfRawData):
            vaddr = pe.OPTIONAL_HEADER.ImageBase + pos - s.PointerToRawData + s.VirtualAddress
            print("In section %s at address 0x%x" % (s.Name, vaddr))
