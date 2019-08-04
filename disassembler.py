from collections import OrderedDict
from capstone import *
import binascii
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
        if dest_raw[0] == '$':
            try:
                dest = int(dest_raw[1:], 16)
            except ValueError:
                return
        else:
            return

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

    def display(self):
        """
        Print disassembled code to terminal
        """
        ordered_nodes = OrderedDict(sorted(self.disas_nodes.items()))
        last_node_end = None
        for start in ordered_nodes:
            if last_node_end and last_node_end != start:
                print("{}:\n  ...\n".format(hex(last_node_end)))

            last_node_end = ordered_nodes[start]['end']

            print("{} <{}>:".format(hex(start)[2:].rjust(6, '0'), ordered_nodes[start]['name']))
            for instr in ordered_nodes[start]['instrs']:
                print("  {}:\t{}\t{}\t{}".format(
                    hex(instr.address)[2:].rjust(6, '0'),
                    binascii.hexlify(instr.bytes).decode().ljust(16, ' '),
                    instr.mnemonic,
                    instr.op_str)
                )

            print()

        if last_node_end and last_node_end != self.context['Header']['RomEnd']:
            print("{}:\n  ...\n".format(hex(last_node_end)[2:].rjust(6, '0')))
