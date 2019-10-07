#!/usr/bin/env python3
import sys
import os
import argparse
import sqlite3
from shutil import copyfile


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert iOS Backup to flat files')
    parser.add_argument("INPUT_FOLDER", help="Folder of the iOS backup extracted")
    parser.add_argument("OUTPUT_FOLDER", help="Output folder")
    parser.add_argument("--verbose", "-v", action="store_true",
            help="Verbose mode")
    args = parser.parse_args()

    if not os.path.isdir(args.INPUT_FOLDER):
        print("Invalid input folder")
        sys.exit(-1)
    if not os.path.isdir(args.OUTPUT_FOLDER):
        print("Invalid output folder")
        sys.exit(-1)

    # Check if there is the Manifest.db file
    manifest = os.path.join(args.INPUT_FOLDER, "Manifest.db")
    if not os.path.isfile(manifest):
        if os.path.isfile(os.path.join(args.INPUT_FOLDER, "Manifest.mbdb")):
            print("Manifest.mbdb not implemented yet, sorry")
            sys.exit(-1)
        else:
            print("Manifest file not found, something is wrong")
            sys.exit(-1)

    conn = sqlite3.connect(manifest)
    c = conn.cursor()
    copied = 0
    not_found = 0
    for row in c.execute('select * from Files'):
        # Test if file exists
        infile = os.path.join(args.INPUT_FOLDER, row[0][0:2], row[0])
        if os.path.isfile(infile):
            if "/" in row[2]:
                # Make directories
                dirpath = os.path.join(args.OUTPUT_FOLDER, os.path.dirname(row[2]))
                if not os.path.isdir(dirpath):
                    os.makedirs(dirpath)
            copyfile(infile, os.path.join(args.OUTPUT_FOLDER, row[2]))
            copied += 1
            if args.verbose:
                print("Copied {} to {}".format(row[0], row[2]))
        else:
            if args.verbose:
                print("File {} not found".format(row[0]))
            not_found += 1

    print("{} files not found".format(not_found))
    print("{} files copied".format(copied))
