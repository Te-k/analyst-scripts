import argparse
import pefile
import os

def get_imphash(exe_path):
    try:
        pe = pefile.PE(exe_path)
        return pe.get_imphash()
    except pefile.PEFormatError:
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some Pe files')
    parser.add_argument('TARGET', help='Target file or folder')
    args = parser.parse_args()

    if os.path.isfile(args.TARGET):
        res = get_imphash(args.TARGET)
        if res:
            print("{} - {}".format(args.TARGET, res))
        else:
            print("{} - Not a PE file".format(args.TARGET))
    elif os.path.isdir(args.TARGET):
        for r, d, f in os.walk(args.TARGET):
            for file in f:
                res = get_imphash(os.path.join(r, file))
                if res:
                    print("{} - {}".format(file, res))
                else:
                    print("{} - Not a PE file".format(file))
