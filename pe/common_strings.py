#!/usr/bin/env python3
import argparse
import re
import string

def strings(data):
    # Inspired by https://github.com/Neo23x0/yarGen/blob/master/yarGen.py
    strings_full = re.findall(b"[\x1f-\x7e]{6,}", data)
    strings_wide = re.findall(b"(?:[\x1f-\x7e][\x00]){6,}", data)
    return strings_full, strings_wide

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('FILE', nargs='+',
        help='File to be processed')
    args = parser.parse_args()

    if len(args.FILE) < 2:
        print("You need at least 2 files")
    else:
        ascii_strings = None
        wide_strings = None
        for f in args.FILE:
            with open(f, 'rb') as fin:
                print("Reading {}".format(f))
                asciii, wide = strings(fin.read())
                if ascii_strings:
                    ascii_strings = ascii_strings.intersection(asciii)
                else:
                    ascii_strings = set(asciii)
                if wide_strings:
                    wide_strings = wide_strings.intersection(wide)
                else:
                    wide_strings = set(wide)
        i = 0
        for s in ascii_strings:
            print("$string{} = \"{}\" ascii".format(i, s.decode('utf-8')))
            i += 1
        for s in wide_strings:
            print("$string{} = \"{}\" wide".format(i, s.decode('utf-16')))
            i += 1
