import argparse
import struct

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Replace the entry point of an exe')
    parser.add_argument('EXEFILE', help='Exe file')
    parser.add_argument('ADDR', help='Address in hexdecimal')
    args = parser.parse_args()

    ep = int(args.ADDR, 16)
    ep_address = 0x138

    with open(args.EXEFILE, 'rb') as f:
        data = f.read()

    print("Current entry point: {}".format(hex(struct.unpack('I', data[ep_address:ep_address+4])[0])))
    new = bytearray(data)
    new[ep_address:ep_address+4] = struct.pack('I', ep)

    with open(args.EXEFILE + '.patch', 'wb+') as f:
        f.write(new)
    print("Patched in {}".format(args.EXEFILE+".patch"))

