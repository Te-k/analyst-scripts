import lief
import argparse
import hashlib


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Print Mach-O information')
    parser.add_argument('MACHO', help='Mach-o file')
    args = parser.parse_args()


    binary = lief.parse(args.MACHO)
    print(binary)
