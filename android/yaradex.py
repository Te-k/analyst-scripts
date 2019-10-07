#!/usr/bin/env python3
import yara
import os
import sys
import argparse
from androguard.core.bytecodes.apk import APK
from androguard.core import androconf


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("YARARULE", help="Path of the yara rule file")
    parser.add_argument("PATH", help="Path of the executable to check")
    args = parser.parse_args()


    if not os.path.isfile(args.PATH):
        print("Invalid snoopdroid dump path")
        sys.exit(-1)
    if not os.path.isfile(args.YARARULE):
        print("Invalid path for yara rule")
        sys.exit(-1)

    if androconf.is_android(args.PATH) != "APK":
        print("This is not an APK file")
        sys.exit(-1)

    rules = yara.compile(filepath=args.YARARULE)

    apk = APK(args.PATH)
    dex = apk.get_dex()
    res = rules.match(data=dex)
    if len(res) > 0:
        print("Matches: {}".format(", ".join([r.rule for r in res])))
