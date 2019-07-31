from capstone import *

def disassemble_all(context):
    """
    Dissassemble all discovered code in the ROM
    """
    md = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN|CS_MODE_M68K_000)
    for instr in md.disasm(context['Code'], context['ProgramStart']):
        print("0x%x:\t%s\t%s" %(instr.address, instr.mnemonic, instr.op_str))
