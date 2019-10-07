#! /usr/bin/python3
import os
import sys
import argparse
import hashlib
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


def get_dex(apk_path):
    """
    Extract the package name of an APK
    """
    a = APK(apk_path)
    return a.get_dex()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("PATH", help="Path to a file or folder")
    args = parser.parse_args()

    if os.path.isdir(args.PATH):
        for f in os.listdir(args.PATH):
            if os.path.isfile(f):
                apk_path = os.path.join(args.PATH, f)
                if androconf.is_android(apk_path) == 'APK':
                    dex_filename = os.path.splitext(apk_path)[0] + '.classes.dex'
                    if not os.path.exists(dex_filename):
                        with open(dex_filename, 'wb') as f:
                            f.write(get_dex(apk_path))
                        print("Dex file {} created".format(dex_filename))
    elif os.path.isfile(args.PATH):
        dex_filename = args.PATH.splitext(apk_path)[0] + '.classes.dex'
        if os.path.exists(dex_filename):
            print("{} already exist".format(dex_filename))
        else:
            with open(dex_filename, 'wb') as f:
                f.write(get_dex(args.PATH))
            print("Dex file {} created".format())
    else:
        print("Invalid path")
        sys.exit(-1)
