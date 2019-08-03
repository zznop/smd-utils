from capstone import *
import re

class Operation(object):
    def branches():
        return [
            'jmp', 'jsr',
            'bra', 'bsr', 'bhi', 'bls', 'bcc', 'bcs', 'bne', 'beq',
            'bvc', 'bvs', 'bpl', 'bmi', 'bge', 'blt', 'bgt', 'ble',
            'dbt', 'dbf', 'dbhi', 'dbls', 'dbcc', 'dbcs', 'dbne',
            'dbeq', 'dbvc', 'dbvs', 'dbpl', 'dbmi', 'dbge', 'dblt',
            'dbgt', 'dble'
        ]

    def returns():
        return ['rtd', 'rte', 'rtr', 'rts']

    def exceptions():
        return ['trap', 'illegal', 'bkpt']

class Disassembler:
    def __init__(self, context):
        self.context = context
        self.branch_targets = dict()
        self.md = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN|CS_MODE_M68K_000)

    def disassemble_data(self, start, name=None):
        """
        Disassembles data beginning at the specified start index
        """
        if name:
            print("{} <{}>:".format(hex(start)[2:].rjust(6, '0'), name))
        for instr in self.md.disasm(self.context['Raw'][start:], start):
            print("  0x%x:\t%s\t%s" %(instr.address, instr.mnemonic, instr.op_str))
            if instr.mnemonic in Operation.returns():
                break
        print()

    def disassemble_all(self):
        """
        Dissassemble all discovered code in the ROM
        """
        self.disassemble_data(self.context['ProgramStart'], name='ProgramStart')
        self.disassemble_data(self.context['VectorTable']['VectPtrIrqL4'], name='HBlank')
        self.disassemble_data(self.context['VectorTable']['VectPtrIrqL6'], name='VBlank')

