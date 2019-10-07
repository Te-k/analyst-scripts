#! /usr/bin/python2
import csv
import argparse
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert a csv to a Markdown file')
    parser.add_argument('CSVFILE', help='CSV file to be converted')
    parser.add_argument('-n', '--no-header', help="No header in the CSV file", action="store_true")
    parser.add_argument('-d', '--delimiter', default=",",
            help="No header in the CSV file")

    args = parser.parse_args()

    firstline = not args.no_header
    with open(args.CSVFILE, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        for row in reader:
            print("|%s|" % "|".join(row))
            if firstline:
                print(("|:---------------------" * len(row)) + "|")
                firstline = False

