import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='XOR a string with all 256 possibilities')
    parser.add_argument('STRING', help="string to xor")
    args = parser.parse_args()

    for i in range(256):
        bb = bytearray()
        aa = args.STRING.encode("utf-8")
        for aaa in aa:
            bb.append(aaa ^ i)
        print(bb.decode('utf-8', errors="replace"))
