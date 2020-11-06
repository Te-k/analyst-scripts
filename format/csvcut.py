import csv
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cut columns from a CSV file')
    parser.add_argument('FILE', help='CSV file')
    parser.add_argument('--delimiter', '-d', default=',', help='Delimiter')
    parser.add_argument('--quotechar', '-q', default='"', help="Quote char")
    parser.add_argument('--cut', '-c', type=int, help="Column to get")
    parser.add_argument('--uniq', '-u', action='store_true', help="Only print uniq values")
    args = parser.parse_args()

    lines = set()

    with open(args.FILE) as csvfile:
        reader = csv.reader(csvfile, delimiter=args.delimiter, quotechar=args.quotechar)
        for row in reader:
            if args.uniq:
                lines.add(row[args.cut])
            else:
                print(row[args.cut])

    if args.uniq:
        for d in lines:
            print(d)
