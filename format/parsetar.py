import os
import argparse
import math
import re
from datetime import datetime

def testheader(hd):
    r = re.match(b".{100}[0-9]{6} \x00[0-9\x00]{7}\x00[0-9\x00]{7}\x00[0-9]{11}\x00[0-9\x00]{11}\x00\d{6}\x00 \d\x00{100}", hd)
    return (r is not None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process a TAR archive')
    parser.add_argument('FILE', help='TAR File')
    parser.add_argument('--verbose', '-v', action="store_true", help="Verbose mode")
    args = parser.parse_args()

    size = os.path.getsize(args.FILE)
    fin = open(args.FILE, 'rb')

    i = 0
    nextheader = False
    while (i + 512) < size:
        header = fin.read(512)
        if len(header) < 512:
            print("Done")
            break
        if header == b"\x00"*512:
            # Sometimes a tar archive ends with an empty header
            print("{} - empty header".format(i))
            i += 512
            continue

        if header[345] != 0:
            name = header[345:500].decode('utf-8').strip("\x00") + "/" + header[0:100].decode('utf-8').strip("\x00")
        else:
            name = header[0:100].decode('utf-8').strip("\x00")

        fs = int(header[124:124+12].strip(b"\x00").decode('utf-8'), 8)
        mtime = datetime.fromtimestamp(int(header[136:136+12], 8))
        flag = header[156]
        nb = math.ceil(fs / 512)
        if flag == 120:
            # extension header for next file
            data = fin.read(512*nb)
            nextheader = {}
            j = 0
            headone = False
            while not headone:
                if data[j] == 0:
                    headone = True
                    break
                length = int(data[j:j+3])
                if length < 99:
                    entry = data[j+3:j+length-3]
                else:
                    entry = data[j+4:j+length-4]
                entry = entry.decode("utf-8", errors="ignore")
                j += length
                entry = entry.split("=", 1)
                if entry[0].endswith("time"):
                    nextheader[entry[0]] = datetime.fromtimestamp(float(entry[1]))
                else:
                    nextheader[entry[0]] = entry[1]
        else:
            #if testheader(header):
                #print("{:10d} - {} - {} bytes (OK)".format(i, name, fs))
            #else:
                #print("{:10d} - {} - {} bytes (NOPE)".format(i, name, fs))
            print("{:10d} - {} - {} bytes".format(i, name, fs))
            if nextheader != False:
                if args.verbose:
                    for entry in nextheader:
                        print("-{} : {}".format(entry, nextheader[entry]))
                else:
                    if "name" in nextheader:
                        print("-name: {}".format(nextheader["name"]))
            nextheader = False
            data = fin.read(512*nb)
        i += 512 + 512*nb

