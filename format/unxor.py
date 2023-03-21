import argparse
import base64


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='XOR a string with all 256 possibilities')
    parser.add_argument('STRING', help="string to xor")
    parser.add_argument('--base64', '-b', action="store_true", help="Base64 decode the string first")
    args = parser.parse_args()

    if args.base64:
        entry = base64.b64decode(args.STRING)
    else:
        entry = args.STRING.encode("utf-8")

    for i in range(256):
        bb = bytearray()
        aa = entry
        for aaa in aa:
            bb.append(aaa ^ i)
        print(bb.decode('utf-8', errors="replace"))
