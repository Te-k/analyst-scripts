import os
import re
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('FILE', help="File to search for hashes")
    args = parser.parse_args()

    with open(args.FILE) as f:
        data = f.read().split("\n")

    hashes = set()

    for d in data:
        r = re.search("[0-9a-fA-F]{64}", d)
        if r:
            hashes.add(r.group())

    for h in hashes:
        print(h)
