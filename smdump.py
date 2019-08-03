#/usr/bin/python3

import argparse
import binascii
import re
from loader import *
from disassembler import *

__author__     = 'zznop'
__copyright__  = 'Copyright 2019, zznop'
__license__    = 'GPL'
__version__    = '1.0'
__email__      = 'zznop0x90@gmail.com'

def parse_args():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--disassemble', action='store_true',
        help='Display assembler contents of the executable section')
    parser.add_argument('-x', '--header', action='store_true',
        help='Display the contents of the header')
    parser.add_argument('file', type=argparse.FileType('rb'),
        help='Path to a SMD ROM file')
    return parser.parse_args()

def display_header(context):
    """
    Display the ROM header
    """
    print('\nROM Header:')
    for name, value in context['Header'].items():
        line = "  {}".format(name)
        line = line.ljust(24)
        if name == 'SramInfo' or name == 'IOSupport':
            hexstr = binascii.hexlify(value)
            hexbytes = re.findall('.{1,2}', hexstr)
            line += '\\x' + '\\x'.join(hexbytes)
        elif type(value) == str:
            line += value.decode('utf-8')
        elif type(value) == int:
            line += hex(value)
        print(line)
    print

def main():
    """
    Main routine of the application
    """
    args = parse_args()
    data = args.file.read()
    context = SMDLoader.load(data)
    #display_header(context)
    disas = Disassembler(context)
    disas.disassemble_all()

if __name__ == '__main__':
    main()