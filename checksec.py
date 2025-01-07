from pwn import *

def check_security(binary_path):
    try:
        binary = ELF(binary_path)
        print(binary.checksec())
        
    except Exception as e:
        print(f"Error analyzing binary: {e}")