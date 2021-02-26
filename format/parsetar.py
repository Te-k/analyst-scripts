import os
import argparse
import math
import re

def testheader(hd):
    r = re.match(b".{100}[0-9]{6} \x00[0-9\x00]{7}\x00[0-9\x00]{7}\x00[0-9]{11}\x00[0-9\x00]{11}\x00\d{6}\x00 \d\x00{100}", hd)
    return (r is not None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process a TAR archive')
    parser.add_argument('FILE', help='TAR File')
    args = parser.parse_args()

    size = os.path.getsize(args.FILE)
    fin = open(args.FILE, 'rb')

    i = 0
    nextname = False
    while (i + 512) < size:
        header = fin.read(512)
        if nextname is not False:
            name = nextname
            nextname = False
        else:
            if header[345] != 0:
                name = header[345:500].decode('utf-8').strip("\x00") + "/" + header[0:100].decode('utf-8').strip("\x00")
            else:
                name = header[0:100].decode('utf-8').strip("\x00")
        fs = int(header[124:124+12].strip(b"\x00").decode('utf-8'), 8)
        flag = header[156]
        nb = math.ceil(fs / 512)
        if flag == 120:
            # extension header for next file
            data = fin.read(512*nb)
            data = data.strip(b"\x00").decode("utf-8").split()
            nn = [d for d in data if d.startswith('path')]
            if len(nn) > 0:
                nn = nn[0]
                nextname = nn.split("=")[1]
            else:
                nextname = False
        else:
            nextname = False
            if testheader(header):
                print("{:10d} - {} - {} bytes (OK)".format(i, name, fs))
            else:
                print("{:10d} - {} - {} bytes (NOPE)".format(i, name, fs))
            data = fin.read(512*nb)
        i += 512 + 512*nb

