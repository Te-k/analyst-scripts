import os
import sys
import argparse
import math
import re

def testheader(hd):
    r = re.match(b".{100}[0-9]{6} \x00[0-9\x00]{7}\x00[0-9\x00]{7}\x00[0-9]{11}\x00[0-9\x00]{11}\x00\d{6}\x00 \w\x00{100}", hd)
    return (r is not None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Repair a TAR archive')
    parser.add_argument('FILE', help='TAR File')
    parser.add_argument('OUTPUT', help='TAR File')
    args = parser.parse_args()

    size = os.path.getsize(args.FILE)
    fin = open(args.FILE, 'rb')
    fout = open(args.OUTPUT, 'wb+')

    i = 0
    prev = 0
    data = b""
    while (i + 512) < size:
        header = fin.read(512)
        if not testheader(header):
            if header == b'\x00'*len(header):
                print("Final empty header, it should be good, finger crossed")
                fout.write(data)
                fout.write(fin.read())
                sys.exit(1)
            print("Broken file entry at {} (wrong header at {})".format(prev, i))
            fin.seek(prev)
            hd = fin.read(512)
            fs = int(hd[124:124+12].strip(b"\x00").decode('utf-8'), 8)
            nb = math.ceil(fs / 512)
            data = fin.read(3000000)
            r = re.search(b".{100}[0-9]{6} \x00[0-9\x00]{7}\x00[0-9\x00]{7}\x00[0-9]{11}\x00[0-9\x00]{11}\x00\d{6}\x00 \w\x00{100}", data)
            if r:
                j = r.span()[0]
                print("Next header found")
                print(data[j:j+200])
                if j > (nb * 512):
                    # There is some extra data we should remove
                    print("Too much data")
                    data = data[:nb*512]
                else:
                    # There is not enough data
                    print("Not enough data")
                    data = data[:j] + b"\x00"*((nb*512) - j)
                fin.seek(prev)
                fin.read(512 + j)
                i = prev + 512 + j
            else:
                # broken
                print("No header found, quitting")
                fout.write(data)
                fout.write(fin.read())
                sys.exit(1)
        else:
            fout.write(data)
            fout.write(header)
            fs = int(header[124:124+12].strip(b"\x00").decode('utf-8'), 8)
            nb = math.ceil(fs / 512)
            data = fin.read(512*nb)
            # impossible to add without being sure the next header is good,
            # so saving here and adding later
            #fout.write(data)
            prev = i
            i += 512 + 512*nb
