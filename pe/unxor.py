import argparse


PEHEADER = b'MZ\x90\x00\x03\x00\x00\x00'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Unxor a PE file')
    parser.add_argument('FILE', help='Xor encoded PE file')
    args = parser.parse_args()

    with open(args.FILE, 'rb') as f:
        data = f.read()

    res = [a^b for a, b in zip(PEHEADER, data[0:len(PEHEADER)])]
    if res.count(res[0]) == len(res):
        # Xor key found
        print("Key identified {}".format(hex(res[0])))
        with open("a.out", "wb+") as f:
            f.write(bytearray([a^res[0] for a in data]))
        print("Decoded payload written in a.out")
    else:
        print("Key not found")
