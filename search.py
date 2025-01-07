from pwn import *
from termcolor import colored
import argparse

context.log_level = logging.CRITICAL

def search_gadget(binary_path, gadget=None):

    binary = ELF(binary_path)
    rop = ROP(binary)

    print(f"{colored('[+]', 'green')} Using: {binary_path}")

    if gadget:
        print(f"{colored('[+]', 'green')} Searching for gadgets containing: '{gadget}'\n")
    else:
        print(f"{colored('[+]', 'green')} Extracting all gadgets...\n")

    found = False
    total_gadgets = 0

    for gadget_addr, gadget_obj in rop.gadgets.items():
        instructions = "; ".join(gadget_obj.insns)
        if not gadget or gadget in instructions:
            found = True
            total_gadgets += 1
            print(f"{colored('0x%08x' % gadget_addr, 'cyan')}: {instructions}")

    if not found:
        if gadget:
            print(f"{colored('[-]', 'yellow')} No gadgets found containing: '{gadget}'.")
        else:
            print(f"{colored('[-]', 'yellow')} No gadgets found in the binary.")
    else:
        print(f"\n{colored('[+]', 'green')} Total gadgets found: {total_gadgets}")

