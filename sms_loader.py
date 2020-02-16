import idaapi
import ida_funcs

"""
sms_loader.py is a IDA loader for SEGA Master System ROMs

To use this loader, copy it to your IDA "loaders" directory
"""

def accept_file(li, name):
    """
    Determine if the input is a valid SMS ROM

    :param li: Loader input
    :param filename: Name of file
    :return: Dictionary containing file information if loadable, otherwise 0
    """

    magic = "TMR SEGA"
    magic_len = len(magic)
    size = li.size()
    for offset in [0x1ff0, 0x3ff0, 0x7ff0]:
        if offset + magic_len > size:
            return 0

        li.seek(offset)
        try:
            if li.read(magic_len).decode('utf-8') != magic:
                continue
        except UnicodeError:
            continue

        return{
            'format': 'SMS ROM',
            'processor': 'z80',
            'options': 1|idaapi.ACCEPT_FIRST
        }

    return 0

def create_reset_vectors():
    """
    Disassemble and name reset vectors (except RST0, which will be set as entry)
    """

    ida_funcs.add_func(0x0008)
    idaapi.set_name(0x0008, 'RST1', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_funcs.add_func(0x0010)
    idaapi.set_name(0x0010, 'RST2', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_funcs.add_func(0x0018)
    idaapi.set_name(0x0018, 'RST3', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_funcs.add_func(0x0020)
    idaapi.set_name(0x0020, 'RST4', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_funcs.add_func(0x0028)
    idaapi.set_name(0x0028, 'RST5', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_funcs.add_func(0x0030)
    idaapi.set_name(0x0030, 'RST6', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    ida_funcs.add_func(0x0038)
    idaapi.set_name(0x0038, 'RST7', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)

def create_io_ports():
    """
    Define I/O ports

    TODO: This can be built out further
    """

    idaapi.set_name(0x0006, 'PSG', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x003e, 'YM2413', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x003f, 'JOYSTICK_IO_CTRL', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x007e, 'V_COUNTER', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x007f, 'H_COUNTER', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x00be, 'VDP_DATA', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x00bf, 'VDP_CTRL', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x00dc, 'IO_PORT_A_B', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)
    idaapi.set_name(0x00dd, 'IO_PORT_B_MISC', idaapi.SN_NOWARN|idaapi.SN_NOLIST|idaapi.SN_NOCHECK)

def load_file(li, neflags, format):
    """
    Load the SEGA Master System ROM
    :param li: Loader input
    :param neflags:
    :param format:
    :return: 1 on success, otherwise 0
    """

    idaapi.set_processor_type('z80', idaapi.SETPROC_LOADER)
    is_reload = (neflags & idaapi.NEF_RELOAD) != 0
    if is_reload:
        return 1

    # Create ROM segment
    rom_seg = idaapi.segment_t()
    rom_seg.start_ea = 0x0000
    rom_seg.end_ea = 0xbfff
    rom_seg.bitness = 0
    idaapi.add_segm_ex(rom_seg, 'ROM', 'CODE', idaapi.ADDSEG_OR_DIE)

    # Read file into ROM segment
    li.seek(0)
    li.file2base(0, 0, li.size(), False)

    # Create RAM Segment
    ram_seg = idaapi.segment_t()
    ram_seg.start_ea = 0xc000
    ram_seg.end_ea = 0xdfff
    ram_seg.bitness = 0
    idaapi.add_segm_ex(ram_seg, 'RAM', 'DATA', idaapi.ADDSEG_OR_DIE)

    # Create RAM mirror segment
    ram_mirror_seg = idaapi.segment_t()
    ram_mirror_seg.start_ea = 0xe000
    ram_mirror_seg.end_ea = 0xffff
    ram_mirror_seg.bitness = 0
    idaapi.add_segm_ex(ram_mirror_seg, 'RAM_MIRROR', 'DATA', idaapi.ADDSEG_OR_DIE)

    # Define the I/O ports
    create_io_ports()

    # Disassemble reset vectors
    create_reset_vectors()

    # Specify entry
    idaapi.add_entry(0x0000, 0x0000, 'RST0', 1)
    return 1
