import lief
import argparse
import os


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rename the __cfstring section in __text')
    parser.add_argument('MACHO', help='Mach-O binary')
    parser.add_argument('NAME', help='Name of the section')
    parser.add_argument('NEWNAME', help='Name of the section')
    args = parser.parse_args()

    binary = lief.parse(args.MACHO)
    found = False
    for s in binary.sections:
        if s.name == args.NAME:
            s.name = args.NEWNAME
            print("Section found")
            found = True
            break

    if not found:
        print("This section was not found in this binary")
    else:
        binary.write(args.MACHO + "_renamed")

