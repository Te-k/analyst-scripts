import csv
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('COLUMN', type=int, default=0,
            help='Column of the file')
    parser.add_argument('FILE', help='CSV file')
    parser.add_argument('--delimiter', '-d', default=',', help='Delimiter')
    parser.add_argument('--quotechar', '-q', default='"', help='Quote char')
    args = parser.parse_args()

    with open(args.FILE) as csvfile:
        reader = csv.reader(csvfile, delimiter=args.delimiter, quotechar=args.quotechar)

        for row in reader:
            print(row[args.COLUMN])


