import argparse


ELFHEADER = b'\x7fELF\x02\x01\x01\x00\x00\x00'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Unxor an ELF file')
    parser.add_argument('FILE', help='Xor encoded ELF file')
    args = parser.parse_args()

    with open(args.FILE, 'rb') as f:
        data = f.read()

    res = [a^b for a, b in zip(ELFHEADER, data[0:len(ELFHEADER)])]
    if res.count(res[0]) == len(res):
        # Xor key found
        print("Key identified {}".format(hex(res[0])))
        with open("a.out", "wb+") as f:
            f.write(bytearray([a^res[0] for a in data]))
        print("Decoded payload written in a.out")
    else:
        print("Key not found")
