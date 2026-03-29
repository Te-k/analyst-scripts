import argparse
import os
import sys
import re


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Unquarantine files from Defender for Mac OS')
    parser.add_argument('FILE', help="Input file")
    parser.add_argument('--output', '-o', help="Output file", default=None)
    args = parser.parse_args()

    if not os.path.isfile(args.FILE):
        print("This file doesn't exists")
        sys.exit(1)

    filename = os.path.basename(args.FILE)
    if not re.match(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", filename):
        print("Warning: filename doesn't match the Defender quarantined filename pattern")

    with open(args.FILE, "rb") as f:
        data = f.read()

    output_file = bytearray()

    output_filename = args.FILE + ".out"
    if args.output:
        output_filename = args.output

    if os.path.isfile(output_filename):
        print("A file named {} already exists, quitting...".format(output_filename))
        sys.exit(1)

    for b in data:
        output_file.append(b ^ 0x25)

    with open(output_filename, "wb") as f:
        f.write(output_file)
    print("File extracted in {}".format(output_filename))
