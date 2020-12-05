import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Count number of bytes per values in a file')
    parser.add_argument('FILE', help='A file, any file')
    args = parser.parse_args()

    values = [0]*256

    with open(args.FILE, 'rb') as f:
        data = f.read()
    for d in data:
        values[d] += 1

    for i, d in enumerate(values, start=0):
        print("0x{:02x} - {}".format(i, d))
