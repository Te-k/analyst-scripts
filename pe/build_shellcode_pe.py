import sys
import argparse
from lief import PE


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build a PE from a shellcode')
    parser.add_argument('SHELLCODE',help='Shellcode')
    args = parser.parse_args()

    # Get the shellcode
    with open(args.SHELLCODE, "rb") as f:
        data = f.read()

    binary32 = PE.Binary("pe_from_scratch", PE.PE_TYPE.PE32)

    section_text                 = PE.Section(".text")
    section_text.content         = [c for c in data] # Take a list(int)
    section_text.virtual_address = 0x1000

    section_text = binary32.add_section(section_text, PE.SECTION_TYPES.TEXT)

    binary32.optional_header.addressof_entrypoint = section_text.virtual_address
    builder = PE.Builder(binary32)
    builder.build_imports(True)
    builder.build()
    builder.write("sc_pe.exe")
