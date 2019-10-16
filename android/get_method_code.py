import sys
import os
import argparse
from androguard.core import androconf
from androguard.misc import AnalyzeAPK

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("APK")
    parser.add_argument("CLASS", help="Class name for instance google.a.b.c")
    parser.add_argument("METHOD", help="Method name")
    parser.add_argument("--verbose", "-v", help="Verbose mode", action="store_true")
    parser.add_argument("--bytecode", "-b", help="Give bytecode", action="store_true")
    parser.add_argument("--hex", "-H", help="Give hex string of the bytecode", action="store_true")
    args = parser.parse_args()

    if not os.path.isfile(args.APK):
        print("This file does not exist")
        sys.exit(-1)

    if androconf.is_android(args.APK) != 'APK':
        print("This is not an APK file :o")
        sys.exit(-1)
    else:
        a, d, dx = AnalyzeAPK(args.APK)
        class_name = args.CLASS.replace('.', '/')
        if args.verbose:
            print("Searching for {}".format(class_name))
        cc = [d for d in dx.get_classes() if class_name in d.name]
        if len(cc) == 0:
            print("Class not found")
        else:
            for c in cc:
                methods = [m for m in c.get_methods() if m.get_method().name == args.METHOD]
                print("{} methods found in {}".format(len(methods), c.name))
                for m in methods:
                    m.get_method().show_info()
                    if args.bytecode:
                        for i in m.get_method().get_instructions():
                            print("{:>24} {:20} {:12}".format(
                                i.get_hex(),
                                i.get_name(),
                                i.get_output()
                            ))
                    else:
                        m.get_method().source()
                    if args.hex:
                        print("{{ {} }}".format(
                            ' '.join([k.get_hex() for k in m.get_method().get_instructions()])
                        ))
