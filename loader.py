import struct
from megadrive import *

class SMDLoader(object):
    @staticmethod
    def load(data):
        """
        Load the SMD ROM into memory
        """
        smd_rom = dict()
        smd_rom['StackStart'] = struct.unpack('>I', data[0:4])
        smd_rom['ProgramStart'] = struct.unpack('>I', data[4:8])
        smd_rom['VectorTable'] = SMDVector.unpack(data[8:256])
        smd_rom['Header'] = SMDHeader.unpack(data[256:512])
        smd_rom['Code'] = data[512:]
        return smd_rom
