import struct
from megadrive import *

class SMDLoader(object):
    @staticmethod
    def load(data):
        """
        Load the SMD ROM into memory
        """
        smd_rom = dict()
        smd_rom['StackStart'] = struct.unpack('>I', data[0:4])[0]
        smd_rom['ProgramStart'] = struct.unpack('>I', data[4:8])[0]
        smd_rom['VectorTable'] = SMDVector.unpack(data[8:256])
        smd_rom['Header'] = SMDHeader.unpack(data[256:512])
        smd_rom['Raw'] = data
        return smd_rom
