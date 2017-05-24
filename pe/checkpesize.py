#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import pefile
import argparse
import sys

"""Check of the size of a PE file is correct
Author : Tek <tek@randhome.io>
Date : 4/10/2016
"""

def get_pe_size(pe, verbose=True):
    """Return the PE size obtained from the file itself"""
    return max(map(lambda x: x.PointerToRawData + x.SizeOfRawData, pe.sections))


def display_sections(pe):
    """Display information about the PE sections"""
    print("Name\tVirtualSize\tVirtualAddress\tRawSize\t\tRawAddress")
    for section in pe.sections:
        print("%s\t%s\t\t%s\t\t%s\t\t%s" % (
                section.Name,
                hex(section.Misc_VirtualSize),
                hex(section.VirtualAddress),
                hex(section.PointerToRawData),
                hex(section.SizeOfRawData)
        ))
    print("")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check PE size')
    parser.add_argument('FILE', help='a PE file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet output')
    parser.add_argument('--extra', '-e',  help='Dump extra data in another file')
    parser.add_argument('--write', '-w',  help='Copy the file with the right size')
    args = parser.parse_args()

    fin = open(args.FILE, 'rb')
    data = fin.read()
    fin.close()
    pe = pefile.PE(data=data)

    if not args.quiet:
        display_sections(pe)

    size = get_pe_size(pe)
    if len(data) > size:
        print("%i bytes of extra data (%i while it should be %i)" % (
            len(data) - size,
            len(data),
            size
        ))
        if args.write is not None:
            fout = open(args.write, 'wb')
            fout.write(data[:size])
            fout.close()
            print('Correct PE dumped in %s' % args.write)
        if args.extra is not None:
            fout = open(args.extra, 'wb')
            fout.write(data[size:])
            fout.close()
            print('Dumped extra data in %s' % args.extra)
    else:
        if len(data) == size:
            print('Correct size')
        else:
            print("File too short (%i while it should be %i)" % (len(data), size))

        if args.write is not None or args.extra is not None:
            print('No extradata, can\'t do anything for you, sorry!')
