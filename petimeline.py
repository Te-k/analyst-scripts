#! /usr/bin/python2
import argparse
import pefile
import os
import datetime
from struct import unpack
from binascii import hexlify
from time import gmtime, strftime

def extract_datetime(fpath):
    """
    take a file and return its timestamp
    based on https://gist.github.com/geudrik/03152ba1a148d9475e81
    """
    try:
        handle = open(fpath, 'rb')
        if hexlify(handle.read(2)) != hexlify(u'MZ'):
            handle.close()
            return
    except:
        return

    try:
        handle.seek(60, 0)
        offset = handle.read(4)
        offset = hexlify(offset[::-1])

        if offset == '':
            handle.close()
            return

        offset = int(offset, 16)
        handle.seek(offset+8, 0)
        dword = handle.read(4)
        handle.close()

        t = unpack(">L", dword[::-1])[0]
    except:
        return
    return datetime.datetime.fromtimestamp(t)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a timeline of PE/DLL timestamp')
    parser.add_argument('DIRECTORY',  help='an integer for the accumulator')

    args = parser.parse_args()

    allfiles = {}

    for root, dirs, files in os.walk(args.DIRECTORY):
        for f in files:
            if f[-4:].lower() in [".exe", ".dll"]:
                timestamp = extract_datetime(os.path.join(root, f))
                if timestamp is not None:
                    allfiles[timestamp] = os.path.join(root, f)

    dates = sorted(allfiles.keys())
    for d in dates:
        print("%s - %s" % (d.strftime("%Y-%m-%d %H:%M:%S"), allfiles[d]))
