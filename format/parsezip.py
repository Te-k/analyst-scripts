from struct import unpack
import argparse
import sys


class Buffer(object):
    """
    Buffer that handles bytes objects
    """
    def __init__(self, data: bytes):
        self._data = data
        self._index = 0

    def __len__(self) -> int:
        return len(self._data)

    @property
    def index(self) -> int:
        return self._index

    @index.setter
    def index(self, value: int):
        if value:
            self._index = value

    def read(self, size):
        data = self._data[self._index:self._index + size]
        self._index += size
        return data

    def read_int(self, little: bool = False):
        data, = unpack("<I", self.read(4))
        return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse a ZIP file')
    parser.add_argument('FILE', help="A zip file")
    args = parser.parse_args()

    with open(args.FILE, 'rb') as f:
        data = f.read()

    file = Buffer(data)
    valid_sig = True
    while valid_sig:
        signature, = unpack("I", file.read(4))
        if signature != 0x04034b50:
            print("Invalid signature")
            sys.exit(-1)

        version, flag, compression, mod_time, mod_date, crc, comp_size, uncomp_size, name_length, extra_length = unpack(
            "HHHHHIIIHH",
            file.read(28)
        )
        print(flag)
        print(comp_size)
        print(version)
        print(compression)
        print(name_length)
        print(extra_length)
        name = file.read(name_length)
        print(name)
        file.read(extra_length)
        data = file.read(comp_size)


