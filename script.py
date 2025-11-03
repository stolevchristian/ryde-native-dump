"""
        Yes, the code is a HUGE mess.
        Do I care?...       I DO NOT!
"""

import os
import base64
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

from elftools.elf.elffile import ELFFile

def get_exported_functions(so_file, javaF=False):
    with open(so_file, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".dynsym")
        functions = {sym.name: sym["st_value"] for sym in symtab.iter_symbols() if sym.name and (javaF and "Java" in sym.name)}
    return functions

def read_memory(so_file, offset, size=32):
    with open(so_file, "rb") as f:
        f.seek(offset)
        return f.read(size)

def get_function_size(so_file, func_addr):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    max_scan_size = 1024
    code = read_memory(so_file, func_addr, max_scan_size)
    function_size = 0
    for i in md.disasm(code, func_addr):
        function_size += 4  
        if i.mnemonic == "ret" or i.mnemonic == "br": 
            break

    return function_size

out_j = {}
def disassemble_function(so_file, func_name, func_addr):
    """Disassemble a function and extract referenced strings"""
    func_size = get_function_size(so_file, func_addr)
    code = read_memory(so_file, func_addr, func_size)

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    print(f"\nFunction: {func_name} (Address: {hex(func_addr)})")
    out_j[func_name] = {}
    adrp_flag = False
    adrp_addr = None
    prolg_flag = False
    for i in md.disasm(code, func_addr):
        print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
        if i.mnemonic == "adrp":
            adrp_flag = True
            adrp_addr = int(i.op_str.split(" ")[1][1:], 16)
        elif i.mnemonic == "mrs":
            prolg_flag = True
        elif adrp_flag == True and i.mnemonic == "add":
            print(".rodata ->", hex(adrp_addr + int(i.op_str.split(" ")[2][1:], 16)))
            try:
                if prolg_flag:
                    b_data = read_memory(so_file, adrp_addr + int(i.op_str.split(" ")[2][1:], 16), 102)   
                    out_b = []
                    for i, v in enumerate(b_data):
                        if v == 0: break
                        out_b.append(hex(v))
                    out_j[func_name][len(out_j[func_name])] = out_b
                    prolg_flag = False
                else:
                    string_data = read_memory(so_file, adrp_addr + int(i.op_str.split(" ")[2][1:], 16), 102)
                    str = ""
                    for i,v in enumerate(string_data):
                        if v == 0: break
                        str += chr(v)
                    if "Secret" in func_name:
                        str = base64.b64decode(str)
                    out_j[func_name][len(out_j[func_name])] = str
                    
            except Exception as e:
                pass
        else:
            adrp_flag = False
            prolg_flag = False

if __name__ == "__main__":
    so_file = os.path.join(os.getcwd(), "libryde_native.so")

    functions = get_exported_functions(so_file, True)
    for func_name, func_addr in functions.items():
        disassemble_function(so_file, func_name, func_addr)
    print(out_j)
