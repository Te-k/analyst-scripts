import lief
import os
import argparse
from hashlib import md5


def symhash(path):
    """
    Compute symhash
    Based on https://github.com/threatstream/symhash
    https://www.anomali.com/blog/symhash
    """
    sym_list = []
    binary = lief.parse(path)
    if isinstance(binary, lief.MachO.Binary):
        for s in binary.imported_symbols:
            sym_list.append(s.name)
        return md5(','.join(sorted(sym_list)).encode()).hexdigest()
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Compute Symhash on Mach-O files')
    parser.add_argument('PATH', help="file or folder")
    args = parser.parse_args()

    if os.path.isdir(args.PATH):
        for r, d, f in os.walk(args.PATH):
            for file in f:
                res = symhash(os.path.join(r, file))
                if res:
                    print("{:40} - {}".format(file, res))
                else:
                    print("{:40} - Not a Mach-O file".format(file))
    elif os.path.isfile(args.PATH):
        res = symhash(args.PATH)
        if res:
            print("{} - {}".format(args.PATH, res))
        else:
            print("{} - Not a Mach-O file".format(args.PATH))
    else:
        print("Invalid Path")

