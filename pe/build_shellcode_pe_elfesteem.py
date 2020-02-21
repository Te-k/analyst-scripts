import sys
import argparse
from elfesteem import pe_init

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build a PE from a shellcode')
    parser.add_argument('SHELLCODE',help='Shellcode')
    args = parser.parse_args()

    # Get the shellcode
    with open(args.SHELLCODE, "rb") as f:
        data = f.read()
    # Generate a PE
    pe = pe_init.PE(wsize=32)
    # Add a ".text" section containing the shellcode to the PE
    s_text = pe.SHList.add_section(name=".text", addr=0x1000, data=data)
    # Set the entrypoint to the shellcode's address
    pe.Opthdr.AddressOfEntryPoint = s_text.addr
    # Write the PE to "sc_pe.py"
    open('sc_pe.exe', 'w').write(str(pe))
