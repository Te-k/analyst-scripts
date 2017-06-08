#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import pefile
import argparse
import sys
import hashlib
import datetime

"""Display infos about a PE file
Author : Tek <tek@randhome.io>
Date : 5/10/2016
"""


def display_hashes(data, pe):
    """Display md5, sha1 and sh256 of the data given"""
    for algo in ["md5", "sha1", "sha256"]:
        m = getattr(hashlib, algo)()
        m.update(data)
        print("%s\t%s" % (algo.upper(), m.hexdigest()))
    print("Imphash: %s" % pe.get_imphash())


def display_headers(pe):
    """Display header information"""
    if pe.FILE_HEADER.IMAGE_FILE_DLL:
        print("DLL File! ")
    print("Compile Time: " + str(datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)))


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


def display_imports(pe):
    """Display imports"""
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll)
        for imp in entry.imports:
            print('\t%s %s' % (hex(imp.address), imp.name))


def display_exports(pe):
    """Display exports"""
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print("%s %s %s" % (
                hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                exp.name,
                exp.ordinal
            ))
    except AttributeError:
        return


def resource(level, r):
    """Recursive printing of resources"""
    if hasattr(r, "data"):
        # resource
        offset = r.data.struct.OffsetToData
        size = r.data.struct.Size
        data = pe.get_memory_mapped_image()[offset:offset+size]
        m = hashlib.md5()
        m.update(data)
        print("    "*level + "-%s\t%i\t%i\t%s\t%s\t%s" % (
                str(r.name),
                r.id,
                size,
                m.hexdigest(),
                pefile.LANG.get(r.data.lang, 'UNKNOWN'),
                pefile.get_sublang_name_for_lang(r.data.lang, r.data.sublang)
            )
        )
    else:
        # directory
        if r.name is None:
            print("    "*level + "-" + str(r.id))
        else:
            print("    "*level + "-" + str(r.name))
        for r2 in r.directory.entries:
            resource(level+1, r2)


def display_resources(pe):
    """Display resources"""
    if(len(pe.DIRECTORY_ENTRY_RESOURCE.entries) > 0):
        print("Resources:")
        for r in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            resource(0, r)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Display information about a PE file')
    parser.add_argument('FILE', help='a PE file')
    parser.add_argument('--sections', '-s', action='store_true', help='Only display sections')
    parser.add_argument('--imports', '-i',  action='store_true', help='Display imports only')
    parser.add_argument('--exports', '-e',  action='store_true', help='Display exports only')
    parser.add_argument('--resources', '-r',  action='store_true', help='Display resources only')
    parser.add_argument('--full', '-f',  action='store_true', help='Full dump of all pefile infos')
    args = parser.parse_args()

    fin = open(args.FILE, 'rb')
    data = fin.read()
    fin.close()
    pe = pefile.PE(data=data)

    if args.sections:
        display_sections(pe)
        sys.exit(0)
    if args.imports:
        display_imports(pe)
        sys.exit(0)
    if args.exports:
        display_exports(pe)
        sys.exit(0)
    if args.resources:
        display_resources(pe)
        sys.exit(0)
    if args.full:
        print(pe.dump_info())
        sys.exit(0)

    display_hashes(data, pe)
    print("")
    display_headers(pe)
    print("")
    display_sections(pe)
    print("")
    display_imports(pe)
    print("")
    display_exports(pe)
    print("")
    display_resources(pe)
