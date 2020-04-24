import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Xor a file')
    parser.add_argument('FILE', help='A file')
    parser.add_argument('VALUE', help='Xor value')
    args = parser.parse_args()

    with open(args.FILE, "rb") as f:
        data = f.read()

    if args.VALUE.startswith("0x"):
        value = int(args.VALUE, 16)
    else:
        value = int(args.VALUE)

    res = bytearray()
    for d in data:
        res.append(d ^ value)


    with open("a.out", "wb+") as f:
        f.write(res)
