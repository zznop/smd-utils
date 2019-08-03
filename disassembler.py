from capstone import *
import re

class Operation(object):
    def branches():
        """
        Branch instructions
        """
        return [
            'jmp', 'jsr',
            'bra', 'bsr', 'bhi', 'bls', 'bcc', 'bcs', 'bne', 'beq',
            'bvc', 'bvs', 'bpl', 'bmi', 'bge', 'blt', 'bgt', 'ble',
            'dbt', 'dbf', 'dbhi', 'dbls', 'dbcc', 'dbcs', 'dbne',
            'dbeq', 'dbvc', 'dbvs', 'dbpl', 'dbmi', 'dbge', 'dblt',
            'dbgt', 'dble'
        ]

    def returns():
        """
        Return instructions
        """
        return ['rtd', 'rte', 'rtr', 'rts']

    def exceptions():
        """
        Instructions with exceptional behavior
        """
        return ['trap', 'illegal', 'bkpt']

class Disassembler:
    def __init__(self, context):
        self.context = context
        self.md = Cs(CS_ARCH_M68K, CS_MODE_BIG_ENDIAN|CS_MODE_M68K_000)
        self.disas_nodes = dict()
        self.discovered_nodes = []
        self.processed = []

    def push_discovered_node(self, instr):
        """
        Push new discovered node to discovered nodes list
        """
        dest_raw = [x.strip() for x in instr.op_str.split(',')][-1]
        dest = int(dest_raw[1:], 16)

        # Already in the discovered node list
        if dest in self.discovered_nodes:
            return

        self.discovered_nodes.append(dest)

    def in_disassembled_node(self, addr):
        """
        Check if the addr falls in a node that's already been disassembled
        """
        for start, _dict in self.disas_nodes.items():
            if addr >= start and addr < _dict['end']:
                return True

        return False

    def disassemble_data(self, start, name=None):
        """
        Disassembles data beginning at the specified start offset
        """
        self.disas_nodes[start] = dict()
        self.disas_nodes[start]['instrs'] = []

        if name:
            self.disas_nodes[start]['name'] = name
        else:
            self.disas_nodes[start]['name'] = "sub_{}".format(hex(start)[2:])

        for instr in self.md.disasm(self.context['Raw'][start:], start):
            self.disas_nodes[start]['instrs'].append(instr)

            # Stop disassembling if it's a ret operation
            if instr.mnemonic in Operation.returns():
                break

            # If it's a branch operation, push the destination to the discovered nodes
            if instr.mnemonic.split('.')[0] in Operation.branches():
                self.push_discovered_node(instr)

        self.disas_nodes[start]['end'] = instr.address + instr.size

    def disassemble_all(self):
        """
        Dissassemble all discovered code in the ROM
        """
        self.disassemble_data(self.context['ProgramStart'], name='ProgramStart')
        for key, value in self.context['VectorTable'].items():
            self.disassemble_data(value, name=key)

        _continue = True
        while _continue:
            _continue = False
            _discovered_nodes = self.discovered_nodes # make a copy, because we're going to push back to it
            for dest in _discovered_nodes:
                # Already been disassembled?
                if dest in self.disas_nodes.keys():
                    continue

                # Contained in a node that's already been disassembled?
                if self.in_disassembled_node(dest):
                    continue

                # New node, disassemble it
                self.disassemble_data(dest)
                _continue = True

        for start in sorted(self.disas_nodes.keys()):
            print("{}:".format(self.disas_nodes[start]['name']))
            for instr in self.disas_nodes[start]['instrs']:
                print("  0x%x:\t%s\t%s" %(instr.address, instr.mnemonic, instr.op_str))
            print()
