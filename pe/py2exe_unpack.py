#!/usr/bin/env python3
import argparse
import pe
import struct
import marshal
import six
import imp
import sys
import time
import os
import ntpath
import uncompyle6
import pefile

"""
Script largely copied from https://github.com/matiasb/unpy2exe
Added uncompyle6
"""


class InvalidPy2ExeFile(Exception):
    def __init__(self, message):
        self.message = message
        Exception.__init__(self, message)


class Py2ExeUnpacker(object):
    def __init__(self, filepath):
        self.path = filepath
        self.ignore = ["<install zipextimporter>", "<bootstrap2>", "boot_common.py"]

    def extract_resource(self):
        """
        Convert to PE and extract PYTHONFILE resource
        """
        pe = pefile.PE(self.path)
        if pe.DIRECTORY_ENTRY_RESOURCE.entries[0].name.string.decode('utf-8') != "PYTHONSCRIPT":
            raise InvalidPy2ExeFile("No PYTHONSCRIPT resource")
        else:
            r = pe.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries[0].directory.entries[0]
            offset = r.data.struct.OffsetToData
            size = r.data.struct.Size
            return pe.get_memory_mapped_image()[offset:offset+size]

    def extract_code(self, data):
        """
        Extract code from the resource
        Largely inspired from https://github.com/matiasb/unpy2exe/blob/master/unpy2exe.py
        """
        current = struct.calcsize(b'iiii')
        metadata = struct.unpack(b'iiii', data[:current])

        if metadata[0] != 0x78563412:
            raise InvalidPy2ExeFile("Invalid PYTHONSCRIPT header")

        arcname = ''
        while six.indexbytes(data, current) != 0:
            arcname += chr(six.indexbytes(data, current))
            current += 1
        code_bytes = data[current + 1:]
        code_objects = marshal.loads(code_bytes)
        return code_objects

    def dump_pyc(self, co, output_dir):
        """
        Dump a code object in a pyc file
        Copied from https://github.com/matiasb/unpy2exe/blob/master/unpy2exe.py
        """
        pyc_basename = ntpath.basename(co.co_filename)
        if pyc_basename in self.ignore:
            return
        pyc_name = pyc_basename + '.pyc'

        # Rebuild PYC header
        version = imp.get_magic()
        version_tuple = sys.version_info
        today = time.time()
        header = version + struct.pack(b'=L', int(today))
        if version_tuple[0] == 3 and version_tuple[1] >= 3:
            header += struct.pack(b'=L', len(co.co_code))

        # Write to file
        destination = os.path.join(output_dir, pyc_name)
        pyc = open(destination, 'wb')
        pyc.write(header)
        marshaled_code = marshal.dumps(co)
        pyc.write(marshaled_code)
        pyc.close()
        return destination

    def decompile(self, filepath, output_dir):
        """
        Decompile pyc file with uncompyle6
        """
        uncompyle6.main.main(output_dir, output_dir, [os.path.basename(filepath)], None)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("PEFILE", help="PEFILE to be analyzed")
    parser.add_argument("--output", "-o", default=".",
            help="Output directory")
    args = parser.parse_args()

    if not os.path.isdir(args.output):
        os.mkdir(args.output)

    try:
        py2exe = Py2ExeUnpacker(args.PEFILE)
        data = py2exe.extract_resource()
        objects = py2exe.extract_code(data)
        for o in objects:
            filepath = py2exe.dump_pyc(o, args.output)
            if filepath:
                print("{} extracted".format(filepath))
                py2exe.decompile(filepath, args.output)
                print("{} decompiled".format(filepath[:-1]))
    except InvalidPy2ExeFile as e:
        print("Extraction failed: {}".format(e.message))
