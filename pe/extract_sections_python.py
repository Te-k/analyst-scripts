import os
import argparse
import struct


def get_sections_from_pe(fpath):
    """
    This is a dirty hack
    """
    with open(fpath, 'rb') as f:
        data = f.read()
    pe_addr = struct.unpack('I', data[0x3c:0x40])[0]
    nb_sections = struct.unpack('H', data[pe_addr+6:pe_addr+8])[0]
    optional_header_size = struct.unpack('H', data[pe_addr+20:pe_addr+22])[0]
    section_addr = pe_addr + 24 + optional_header_size
    image_base = struct.unpack('I', data[pe_addr+24+28:pe_addr+24+32])[0]
    i = section_addr
    sections = []
    for j in range(nb_sections):
        sections.append([
            data[i:i+8].decode('utf-8').strip('\x00'),
            struct.unpack('I', data[i+8:i+12])[0], #VirtSize
            struct.unpack('I', data[i+12:i+16])[0], #VirtAddress
            struct.unpack('I', data[i+16:i+20])[0], #RawSize
            struct.unpack('I', data[i+20:i+24])[0], #RawData
            ])
        i += 40
    return sections, image_base


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse sections from a PE file in pure python')
    parser.add_argument('PE', help='PE file')
    args = parser.parse_args()

    sections, image_base = get_sections_from_pe(args.PE)
    for s in sections:
        print(s)
