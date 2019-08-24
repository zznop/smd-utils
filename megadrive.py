import struct
from collections import namedtuple

class SMDVector(object):
    """
    This class is used to parse the SMD ROM vector table
    """

    @staticmethod
    def unpack(data):
        """
        Unpack SEGA Megadrive vector table structure
        """

        fmt = ">IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"
        Names= namedtuple(
            'Names',
            'VectPtrBusError VectPtrAddressError VectPtrIllegalInstruction ' \
            'VectPtrDivisionByZero VectPtrChkException VectPtrTrapVException ' \
            'VectPtrPrivilegeViolation VectPtrTraceException VectPtrLineAEmulator ' \
            'VectPtrLineFEmulator VectUnused00 VectUnused01 ' \
            'VectUnused02 VectUnused03 VectUnused04 ' \
            'VectUnused05 VectUnused06 VectUnused07 ' \
            'VectUnused08 VectUnused09 VectUnused10 ' \
            'VectUnused11 VectPtrSpuriousException VectPtrIrqL1 ' \
            'VectPtrIrqL2 VectPtrIrqL3 VectPtrIrqL4 ' \
            'VectPtrIrqL5 VectPtrIrqL6 VectPtrIrqL7 ' \
            'VectPtrTrap00 VectPtrTrap01 VectPtrTrap02 ' \
            'VectPtrTrap03 VectPtrTrap04 VectPtrTrap05 ' \
            'VectPtrTrap06 VectPtrTrap07 VectPtrTrap08 ' \
            'VectPtrTrap09 VectPtrTrap10 VectPtrTrap11 ' \
            'VectPtrTrap12 VectPtrTrap13 VectPtrTrap14 ' \
            'VectPtrTrap15 VectUnused12 VectUnused13 ' \
            'VectUnused14 VectUnused15 VectUnused16 ' \
            'VectUnused17 VectUnused18 VectUnused19 ' \
            'VectUnused20 VectUnused21 VectUnused22 ' \
            'VectUnused23 VectUnused24 VectUnused25 ' \
            'VectUnused26 VectUnused27'
        )

        return Names._asdict(Names._make(struct.unpack(fmt, data)))


class SMDHeader(object):
    """
    This class is used to parse the SMD ROM header
    """

    @staticmethod
    def unpack(data):
        """
        Unpack SEGA Megadrive ROM header structure
        """

        fmt = ">16s16s48s48s14sH16sIIII12s52s16s"
        Names = namedtuple(
            'Names', 'ConsoleName Copyright DomesticName ' \
            'InternationalName SerialRevision Checksum ' \
            'IOSupport RomStart RomEnd ' \
            'RamStart RamEnd SramInfo ' \
            'Notes Region'
        )

        return Names._asdict(Names._make(struct.unpack(fmt, data)))
