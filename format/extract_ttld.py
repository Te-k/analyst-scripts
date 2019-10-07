#!/usr/bin/env python3
import argparse

# Extract TTLD from a list of domains

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract TTLDs from a list of domains')
    parser.add_argument('FILE', help='an integer for the accumulator')
    args = parser.parse_args()

    with open(args.FILE, 'r') as f:
        data = f.read().split("\n")

    ttlds = set()

    for d in data:
        if d.strip() != "":
            ttlds.add(".".join(d.strip().split(".")[-2:]))

    for ttld in ttlds:
        print(ttld)
