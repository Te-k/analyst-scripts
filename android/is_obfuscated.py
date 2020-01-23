#! /usr/bin/python3
import os
import sys
import argparse
import hashlib
from androguard.misc import AnalyzeAPK
from androguard.core import androconf


def has_classnames_obfuscated(dx):
    """
    Check if the APK has the class names obfuscated
    Count the number of classes with a name of one character
    Returns True of more than 50% of classes have names of 1 char
    """
    cn = [c.name[1:-1].split('/') for c in dx.get_classes()]
    cnn = [len(a.split('$')[0]) for b in cn for a in b]
    return (cnn.count(1) / len(cnn)) > 0.5


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("PATH", help="Path to a file or folder")
    args = parser.parse_args()

    if os.path.isdir(args.PATH):
        for f in os.listdir(args.PATH):
            if os.path.isfile(f):
                if androconf.is_android(os.path.join(args.PATH, f)) == 'APK':
                    a, d, dx = AnalyzeAPK(os.path.join(args.PATH, f))
                    if has_classnames_obfuscated(dx):
                        print('{:45} - OBFUSCATED'.format(f))
                    else:
                        print('{:45} - NOT OBFUSCATED'.format(f))
    elif os.path.isfile(args.PATH):
        a, d, dx = AnalyzeAPK(args.PATH)
        if has_classnames_obfuscated(dx):
            print("Obfuscated")
        else:
            print("Not obfuscated")
    else:
        print("Invalid path")
        sys.exit(-1)
