import lief
import argparse
import hashlib


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Print Mach-O information')
    parser.add_argument('MACHO', help='Mach-o file')
    args = parser.parse_args()


    binary = lief.parse(args.MACHO)

    with open(args.MACHO, 'rb') as f:
        data = f.read()

    # General information -> CPU Type
    # Hash, CPU Type, Size
    print("General Information")
    print("=" * 80)
    for algo in ["md5", "sha1", "sha256"]:
        m = getattr(hashlib, algo)()
        m.update(data)
        print("{:15} {}".format(algo.upper()+":", m.hexdigest()))
    print("{:15} {} bytes".format("Size:", len(data)))
    print("{:15} {}".format("Type:", binary.header.cpu_type.name))
    print("Entry point:\t0x%x" % binary.entrypoint)
    print("")

    # Commands
    print("Commands")
    print("=" * 80)
    for c in binary.commands:
        if c.command.name == "SEGMENT_64":
            print("{:20} {:10} {:5} {:14} {}".format(
                c.command.name,
                c.name if hasattr(c, 'name') else '',
                c.size,
                hex(c.virtual_address) if hasattr(c, 'virtual_address') else "",
                hex(c.file_offset) if hasattr(c, 'file_offset') else "",
                ))
        elif c.command.name in ["LOAD_DYLIB", "LOAD_WEAK_DYLIB"]:
            print("{:20} {} (version {})".format(
                c.command.name,
                c.name,
                ".".join([str(a) for a in c.current_version])
            ))
        elif c.command.name == "UUID":
            print("{:20} {}".format(
                c.command.name,
                ''.join('{:02x}'.format(x) for x in c.uuid)
            ))
        else:
            print("{:20} {:20}".format(
                c.command.name,
                c.name if hasattr(c, 'name') else ''
            ))
    print("")

    # Sections
    print("Sections")
    print("=" * 80)
    print("%-16s %-9s %-12s %-9s %-9s %-25s %s" % ( "Name", "Segname", "VirtAddr", "RawAddr", "Size", "type", "Md5"))
    for s in binary.sections:
        m = hashlib.md5()
        m.update(bytearray(s.content))
        print("%-16s %-9s %-12s %-9s %-9s %-25s %s" % (
            s.name,
            s.segment.name,
            hex(s.virtual_address),
            hex(s.offset),
            s.size,
            str(s.type).replace("SECTION_TYPES.", ""),
            m.hexdigest()
            ))
    print("")

    # Imports (binding infos)
    print("Imports")
    print("=" * 80)
    for f in binary.imported_symbols:
        try:
            print("{:35s} {}".format(f.name, f.binding_info.library.name))
        except lief.not_found:
            print(f.name)


