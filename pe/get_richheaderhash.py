import argparse
import pefile
import os
import hashlib
import struct


def get_richpe_hash(exe_path):
    """Computes the RichPE hash given a file path or data.
    If the RichPE hash is unable to be computed, returns None.
    Otherwise, returns the computed RichPE hash.
    If both file_path and data are provided, file_path is used by default.
    Source : https://github.com/RichHeaderResearch/RichPE
    """
    try:
        pe = pefile.PE(exe_path)
    except pefile.PEFormatError:
        return None

    if pe.RICH_HEADER is None:
        return None

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = pe.RICH_HEADER.values
    if len(rich_fields) % 2 != 0:
        return None

    # The RichPE hash of a file is computed by computing the md5 of specific
    # metadata within  the Rich header and the PE header
    md5 = hashlib.md5()

    # Update hash using @Comp.IDs and masked counts from Rich header
    while len(rich_fields):
        compid = rich_fields.pop(0)
        count = rich_fields.pop(0)
        mask = 2 ** (count.bit_length() // 2 + 1) - 1
        count |= mask
        md5.update(struct.pack("<L", compid))
        md5.update(struct.pack("<L", count))

    # Update hash using metadata from the PE header
    md5.update(struct.pack("<L", pe.FILE_HEADER.Machine))
    md5.update(struct.pack("<L", pe.FILE_HEADER.Characteristics))
    md5.update(struct.pack("<L", pe.OPTIONAL_HEADER.Subsystem))
    md5.update(struct.pack("<B", pe.OPTIONAL_HEADER.MajorLinkerVersion))
    md5.update(struct.pack("<B", pe.OPTIONAL_HEADER.MinorLinkerVersion))
    md5.update(struct.pack("<L", pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    md5.update(struct.pack("<L", pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    md5.update(struct.pack("<L", pe.OPTIONAL_HEADER.MajorImageVersion))
    md5.update(struct.pack("<L", pe.OPTIONAL_HEADER.MinorImageVersion))
    md5.update(struct.pack("<L", pe.OPTIONAL_HEADER.MajorSubsystemVersion))
    md5.update(struct.pack("<L", pe.OPTIONAL_HEADER.MinorSubsystemVersion))

    return md5.hexdigest()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some Pe files')
    parser.add_argument('TARGET', help='Target file or folder')
    args = parser.parse_args()

    if os.path.isfile(args.TARGET):
        res = get_richpe_hash(args.TARGET)
        if res:
            print("{} - {}".format(args.TARGET, res))
        else:
            print("{} - Not a PE file".format(args.TARGET))
        pass
    elif os.path.isdir(args.TARGET):
        for r, d, f in os.walk(args.TARGET):
            for file in f:
                res = get_richpe_hash(os.path.join(r, file))
                if res:
                    print("{} - {}".format(file, res))
                else:
                    print("{} - Not a PE file".format(file))
