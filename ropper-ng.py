from checksec import check_security
import argparse
from termcolor import colored
from pwn import *
import logging
from search import search_gadget

context.log_level = logging.CRITICAL
print("""
o--o                                      
|   |                                     
O-Oo  o-o o-o  o-o  o-o o-o o-o o-o  o--o 
|  \  | | |  | |  | |-' |       |  | |  | 
o   o o-o O-o  O-o  o-o o       o  o o--O 
          |    |                        | 
          o    o        @tankist0x00 o--o 
""")


# Args
parser = argparse.ArgumentParser(description="New generation Ropper with least power but more agile.")
parser.add_argument("binary", help="Path to the binary file")
parser.add_argument("-t", "--type", type=str, help="Rop chain type: mprotect or execve")
parser.add_argument("-g", "--gadget", type=str, help="Gadgets to search")

args = parser.parse_args()


if args.type or args.gadget:
    # Checking Libc.so and version
    print(f"{colored('[+]', 'green')} Getting libc.so..")
    try:
        binary_path = ELF(args.binary)

        if binary_path.libs:
            for lib, path in binary_path.libs.items():
                if "libc.so" in lib:
                    libc_path = lib
                    print(f"{colored('[+]', 'green')} Found libc: {lib}")
        else:
            print(f"{colored('[+]', 'yellow')} No libc.so found in the binary's dependencies.")
    except Exception as e:
        print(f"{colored('[+]', 'yellow')} Error analyzing binary: {e}")

    # print(test_lib)
    # Search gadgets
    search_gadget(libc_path, args.gadget)
else:
    # Checking security of binary
    print(f"{colored('[+]', 'green')} Checking Security of binary..")
    check_security(args.binary)





