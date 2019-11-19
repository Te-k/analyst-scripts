import lief
import argparse
import os
import sys


def print_signature(binary):
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some PE Files')
    parser.add_argument('FILE', help='PE File')
    parser.add_argument('--verbose', '-v', action="store_true", help='PE File')
    args = parser.parse_args()

    if os.path.isdir(args.FILE):
        # Directory, check all
        for f in os.listdir():
            if os.path.isfile(os.path.join(args.FILE, f)):
                binary = lief.parse(os.path.join(args.FILE, f))
                if binary:
                    if len(binary.signature.certificates):
                        print("{} - SIGNED".format(f))
                    else:
                        if args.verbose:
                            print("{} - NOT SIGNED".format(f))
                else:
                    if args.verbose:
                        print("{} - NOT A PE FILE".format(f))
            elif os.path.isdir(os.path.join(args.FILE, f)):
                if args.verbose:
                    print("{} - Directory".format(f))
    elif os.path.isfile(args.FILE):
        binary = lief.parse(args.FILE)
        if len(binary.signature.certificates):
            for crt in binary.signature.certificates:
                print(crt)
        else:
            print("This binary is not signed")
    else:
        print("Invalid file path")
        sys.exit(1)



