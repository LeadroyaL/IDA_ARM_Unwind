# coding=utf-8
from idc import *
from idaapi import *
from PyQt5 import QtWidgets, QtGui

from io import BytesIO
from elftools.elf.elffile import ELFFile
from elftools.elf.structs import ELFStructs
from elftools.ehabi.ehabiinfo import EHABIInfo


class ArmUnwinder:
    def __init__(self):
        self.unwind_caches = list()
        self.pid = get_event_pid()

    def check_pid(self, pid):
        if pid == self.pid:
            return
        print "Pid changed, refresh arm unwind caches."
        self.unwind_caches = list()
        self.pid = pid

    def unwind_all(self):
        self.check_pid(get_event_pid())
        _status = VRSStatus()
        _status.load_ida_registers()
        pc_list = list()
        pc_list.append(GetRegValue("PC"))
        while self.unwind_single_frame(_status):
            pc_value = _status.getRx(_status.PC_INDEX)
            pc_list.append(pc_value)
        return pc_list

    def unwind_single_frame(self, _status):
        # 1. 拿PC
        pc = _status.getRx(_status.PC_INDEX)
        # 2. 查cache
        unwind_item = None
        for unwind_cache in self.unwind_caches:
            if unwind_cache.startEA <= pc < unwind_cache.endEA:
                unwind_item = unwind_cache
                print "found cache", unwind_cache.name
                break
        if unwind_item is None:
            # 2.5 查不到cache就去解析内存
            cache = self.create_unwind_cache(pc)
            if cache is None:
                print "cannot unwind this pc", '%0.8x' % pc
            else:
                print "add", cache.name, "into cache"
                self.unwind_caches.append(cache)
            unwind_item = cache

        # 3. 使用cache
        if unwind_item is None:
            return False
        else:
            entries = unwind_item.entries
            relative_pc = pc - unwind_item.startEA
            for i in range(len(entries) - 1):
                if entries[i].function_offset <= relative_pc < entries[i + 1].function_offset:
                    print 'find entry', entries[i]
                    # 4. 如果entry不包含bytecode
                    if entries[i].bytecode_array is None:
                        print "cannot unwind", entries[i]
                        return False
                    # 4.5 进行unwind
                    if _interp(entries[i].bytecode_array, _status) == URC_FAILURE:
                        raise RuntimeError("interpret fail")
                    lr_value = _status.getRx(_status.LR_INDEX)
                    if lr_value == 0:
                        return False
                    # 5. lr -> pc
                    _status.setRx(_status.PC_INDEX, _lr2pc(lr_value))
                    print 'pc', '%0.8x' % _status.getRx(_status.PC_INDEX)
                    return True
        print "Cannot find entry for pc", '%0.8x' % pc
        return False

    @staticmethod
    def create_unwind_cache(_pc):
        """根据当前 pc，解析对应的 elf，拿到 exception handler entry 表"""
        # 找到 ELF 头
        _header_seg, _seg_name = _getELFHeader(_pc)
        if not _checkELFHeader(_header_seg):
            print "cannot determine ELF header of this module", _seg_name
            return None
        # 稍微加载一小段，用于获得 program headers，没必要加载完
        _header_data = DbgRead(_header_seg.start_ea, min(0x1000, _header_seg.size()))
        _stream = BytesIO(_header_data)

        _elf = MemoryELFFile(_stream)
        _exidx_segment = _elf.get_exidx_segment()
        if _exidx_segment is None:
            print 'cannot get PT_ARM_EXIDX of this module', _seg_name
            return None
        _exidx_offset = _exidx_segment['p_offset']
        _exidx_size = _exidx_segment['p_memsz']
        _load_size = _elf.get_load_segment()['p_memsz']
        _stream.close()

        # 加载整个内存，需要获得 .arm.exidx 和 .arm.extab 的数据
        _load_data = DbgRead(_header_seg.start_ea, _load_size)
        _stream = BytesIO(_load_data)
        _ehabi_info = EHABIInfo(FakeSection(_stream, _exidx_offset, _exidx_size), _elf.little_endian)
        _unwind_entries = [_ehabi_info.get_entry(i) for i in range(_ehabi_info.num_entry())]
        _stream.close()
        return UnwindItem(_header_seg.start_ea, _header_seg.start_ea + _load_size, _seg_name, _unwind_entries)

    @staticmethod
    def pc2frame(_pc):
        name = get_segm_name(getseg(_pc))
        if name == '.text':
            name = get_root_filename()
            base = get_imagebase()
        else:
            base = get_segm_start(_pc)
        relative_pc = _pc - base
        fullpath = get_module_name(base)
        if fullpath == 0:
            fullpath = ""
        return Frame(relative_pc, _pc, name, fullpath)

    @staticmethod
    def pclist2framelist(_pclist):
        return [ArmUnwinder.pc2frame(_pc) for _pc in _pclist]


def pc2func(_pc):
    _func = get_func(_pc)
    if _func is None:
        return ""
    return "%s + %d" % (get_func_name(_pc), _pc - _func.startEA)


class Frame:
    def __init__(self, relative_pc, absolute_pc, name, fullpath):
        self.relative_pc = relative_pc
        self.func_with_offset = pc2func(absolute_pc)
        self.absolute_pc = absolute_pc
        self.name = name
        self.fullpath = fullpath

    def __repr__(self):
        return "%s-%s-%0.8x-%0.8x" % (self.name, self.fullpath, self.relative_pc, self.absolute_pc)


class MemoryELFFile(ELFFile):
    """精简过的 ELFFile，去除里面多余的功能"""

    def __init__(self, stream):
        self.stream = stream
        self._identify_file()
        self.structs = ELFStructs(
            little_endian=self.little_endian,
            elfclass=self.elfclass)

        self.structs.create_basic_structs()
        self.header = self._parse_elf_header()
        self.structs.e_type = self['e_type']
        self.structs.e_machine = self['e_machine']
        self.structs.e_ident_osabi = self['e_ident']['EI_OSABI']
        self.structs._create_phdr()

    def get_load_segment(self):
        return self._get_first_segment_by_type('PT_LOAD')

    def get_exidx_segment(self):
        return self._get_first_segment_by_type('PT_ARM_EXIDX')

    def _get_first_segment_by_type(self, _type):
        for i in range(self.num_segments()):
            seg_header = self._get_segment_header(i)
            seg_type = seg_header['p_type']
            if seg_type == _type:
                return seg_header


class FakeSection:
    """因为无法从内存中恢复完整的 Section，只能手动创建虚假的 Section，填充关键数据"""

    def __init__(self, stream, offset, size):
        self.stream = stream
        self.offset = offset
        self.size = size

    def __getitem__(self, item):
        if item == 'sh_offset':
            return self.offset
        elif item == 'sh_size':
            return self.size


class UnwindItem:
    def __init__(self, _startEA, _endEA, _seg_name, _unwind_entries):
        self.startEA = _startEA
        self.endEA = _endEA
        self.name = _seg_name
        self.entries = _unwind_entries


def _getELFHeader(_pc):
    """
        parameter pc
        return (segment, module_name)
    """
    name = get_segm_name(getseg(_pc))
    if name == '.text':
        # 如果是.text，说明就是正在被分析的文件
        return getseg(get_imagebase()), get_root_filename()
    else:
        # 寻找同名module，通常第一个就是 R+X而且 7FELF
        return get_segm_by_name(name), name


def _checkELFHeader(_seg):
    DWORD_MAGIC = 0x464c457f
    return DWORD_MAGIC == Dword(_seg.startEA)


def _lr2pc(lr_value):
    """lr是下一条指令，arm是-4的位置，thumb可能是-2和-4，需要都尝试一遍"""
    if lr_value & 1 == 0:
        # ARM, 32byte
        return lr_value - 4
    else:
        # thumb, 16byte or 32byte
        test1 = lr_value - 1 - 4
        test2 = lr_value - 1 - 2
        hit1 = False
        hit2 = False
        pc = None
        if Word(test1) & 0b11110 << 11 == 0b11110 << 11 and Word(test1 + 2) & 0b11 << 14 == 0b11 << 14:
            hit1 = True
        if Word(test2) & 0b010001111 << 7 == 0b010001111 << 7:
            hit2 = True
        if hit1 and hit2:
            print "cannot determine -2 or -4"
        elif hit1:
            pc = test1 + 1
        elif hit2:
            pc = test2 + 1
        else:
            raise RuntimeError("disasm result is not BL/BLX", lr_value)
        return pc


class VRSStatus:
    """解释执行用于存放寄存器状态"""

    def __init__(self):
        self._regs = [0] * 16
        self._double_regs = [0] * 32

    VSP_INDEX = 13
    FP_INDEX = 11
    IP_INDEX = 12
    SP_INDEX = 12
    LR_INDEX = 14
    PC_INDEX = 15

    def load_ida_registers(self):
        """从 IDA 读取初始状态"""
        for i in range(16):
            self._regs[i] = GetRegValue("R%d" % i)

    def vsp_mov(self, data):
        self._regs[self.VSP_INDEX] = data

    def vsp_add(self, data):
        self._regs[self.VSP_INDEX] += data

    def vsp_sub(self, data):
        self._regs[self.VSP_INDEX] -= data

    def pop(self, registers):
        # pop uint32 register
        # pop {R0,R1,R2} -> pop R0;pop R1;pop R2
        for i in range(0, 16):
            if registers & (1 << i) != 0:
                self._regs[i] = Dword(self._regs[self.VSP_INDEX])
                self._regs[self.VSP_INDEX] += 4

    def popD(self, registers):
        # pop uint32 register
        # pop {D0,D1,D2} -> pop D0;pop D1;pop D2
        for i in range(0, 32):
            if registers & (1 << i) != 0:
                self._double_regs[i] = Dword(self._regs[self.VSP_INDEX])
                self._double_regs[self.VSP_INDEX] += 4

    def getRx(self, n):
        return self._regs[n]

    def setRx(self, n, value):
        self._regs[n] = value

    def __repr__(self):
        part1 = """R0: %0.8x, R1: %0.8x, R2: %0.8x, R3: %0.8x
R4: %0.8x, R5: %0.8x, R6: %0.8x, R7: %0.8x
R8: %0.8x, R9: %0.8x, R10:%0.8x, FP: %0.8x
IP: %0.8x, SP: %0.8x, LR: %0.8x, PC: %0.8x""" % (
            self._regs[0], self._regs[1], self._regs[2], self._regs[3],
            self._regs[4], self._regs[5], self._regs[6], self._regs[7],
            self._regs[8], self._regs[9], self._regs[10], self._regs[11],
            self._regs[12], self._regs[13], self._regs[14], self._regs[15],)
        if any(s != 0 for s in self._double_regs):
            part2 = """D0: %0.8x, D1: %0.8x, D2: %0.8x, D3: %0.8x
D4: %0.8x, D5: %0.8x, D6: %0.8x, D7: %0.8x
D8: %0.8x, D9: %0.8x, D10: %0.8x, D11: %0.8x
D12: %0.8x, D13: %0.8x, D14: %0.8x, D15: %0.8x
D16: %0.8x, D17: %0.8x, D18: %0.8x, D19: %0.8x
D20: %0.8x, D21: %0.8x, D22: %0.8x, D23: %0.8x
D24: %0.8x, D25: %0.8x, D26: %0.8x, D27: %0.8x
D28: %0.8x, D29: %0.8x, D30: %0.8x, D31: %0.8x""" % (
                self._double_regs[0], self._double_regs[1], self._double_regs[2], self._double_regs[3],
                self._double_regs[4], self._double_regs[5], self._double_regs[6], self._double_regs[7],
                self._double_regs[8], self._double_regs[9], self._double_regs[10], self._double_regs[11],
                self._double_regs[12], self._double_regs[13], self._double_regs[14], self._double_regs[15],
                self._double_regs[16], self._double_regs[17], self._double_regs[18], self._double_regs[19],
                self._double_regs[20], self._double_regs[21], self._double_regs[22], self._double_regs[23],
                self._double_regs[24], self._double_regs[25], self._double_regs[26], self._double_regs[27],
                self._double_regs[28], self._double_regs[29], self._double_regs[30], self._double_regs[31],
            )
            return "%s\n%s" % (part1, part2)
        else:
            return part1


def _register_mask(start, count_minus_one):
    return ((1 << (count_minus_one + 1)) - 1) << start


URC_SUCCESS = 0
URC_FAILURE = 1


def _interp(bytecode_array, status):
    """
    reference: https://github.com/llvm/llvm-project/blob/master/libunwind/src/Unwind-EHABI.cpp
        _LIBUNWIND_EXPORT _Unwind_Reason_Code 
        _Unwind_VRS_Interpret(_Unwind_Context *context, const uint32_t *data, size_t offset, size_t len)
    """
    offset = 0
    finish = False
    wrote_pc = False
    bc_len = len(bytecode_array)
    while offset < bc_len and not finish:
        b = int(bytecode_array[offset])
        offset += 1
        if b & 0x80 == 0:
            if b & 0x40 != 0:
                status.vsp_sub(((b & 0x3f) << 2) + 4)
            else:
                status.vsp_add((b << 2) + 4)
        else:
            if b & 0xf0 == 0x80:
                registers = ((b & 0xf) << 12) | (bytecode_array[offset] << 4)
                offset += 1
                if registers == 0:
                    return URC_FAILURE
                if registers & (1 << 15) != 0:
                    wrote_pc = True
                status.pop(registers)
            elif b & 0xf0 == 0x90:
                reg = b & 0x0f
                if reg == 13 or reg == 15:
                    return URC_FAILURE
                status.vsp_mov(status.getRx(reg))
            elif b & 0xf0 == 0xa0:
                registers = _register_mask(4, b & 0x07)
                if b & 0x08 != 0:
                    registers |= 1 << 14
                status.pop(registers)
            elif b & 0xf0 == 0xb0:
                if b == 0xb0:
                    finish = True
                elif b == 0xb1:
                    registers = bytecode_array[offset]
                    offset += 1
                    if registers & (1 << 15) != 0 or registers == 0:
                        return URC_FAILURE
                    status.pop(registers)
                elif b == 0xb2:
                    addend = 0
                    shift = 0
                    while True:
                        b = bytecode_array[offset]
                        offset += 1
                        addend |= (b & 0x7f) << shift
                        if b & 0x80 == 0:
                            break
                        shift += 7
                    status.vsp_add(0x204 + (addend << 2))
                elif b == 0xb3:
                    b = bytecode_array[offset]
                    offset += 1
                    start = ((b & 0xf0) >> 4)
                    count = ((b & 0x0f) >> 0)
                    status.popD(_register_mask(start, count))
                elif b == 0xb4 or b == 0xb5 or b == 0xb6 or b == 0xb7:
                    return URC_FAILURE
                else:
                    b = bytecode_array[offset]
                    offset += 1
                    status.popD(_register_mask(8, b & 0x07))
            elif b & 0xf0 == 0xc0:
                if b == 0xc0 or b == 0xc1 or b == 0xc2 or b == 0xc3 or b == 0xc4 or b == 0xc5:
                    raise RuntimeError("unsupport wmmxd")
                elif b == 0xc6:
                    raise RuntimeError("unsupport wmmxd")
                elif b == 0xc7:
                    raise RuntimeError("unsupport wmmxd")
                elif b == 0xc8 or b == 0xc9:
                    b = bytecode_array[offset]
                    offset += 1
                    start = 16 + ((b & 0xf0) >> 4)
                    count = ((b & 0x0f) >> 0)
                    status.popD(_register_mask(start, count))
                else:
                    return URC_FAILURE
            elif b & 0xf0 == 0xd0:
                if b & 0x80 != 0:
                    return URC_FAILURE
                status.popD(_register_mask(8, b & 0x07))
            else:
                return URC_FAILURE
    if not wrote_pc:
        status.setRx(status.IP_INDEX, status.getRx(status.LR_INDEX))
    print "interp done, now list registers"
    print status
    return URC_SUCCESS


class ArmUnwindView(PluginForm):
    """GUI container"""
    cols = ['Module', 'Path', 'Position', 'Address']

    def __init__(self, frames):
        super(ArmUnwindView, self).__init__()
        self.tree = None
        self.frames = frames

    def dblclick(self, item):
        """Handle double click event."""
        try:
            if get_imagebase() == 0:
                jumpto(int(item.text(2).split('(')[0], 16))
            else:
                jumpto(int(item.text(3), 16))
        except:
            pass

    def load_data(self):
        x = lambda ea: '0x%X' % ea

        for frame in self.frames:
            item = QtWidgets.QTreeWidgetItem(self.tree)
            item.setText(0, frame.name)
            item.setText(1, frame.fullpath)
            item.setText(2, x(frame.relative_pc) + '(' + frame.func_with_offset + ')')
            item.setText(3, x(frame.absolute_pc))

    def OnCreate(self, form):
        """Called when the plugin form is created"""

        self.parent = self.FormToPyQtWidget(form)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(len(self.cols))
        self.tree.setHeaderLabels(self.cols)
        self.tree.itemDoubleClicked.connect(self.dblclick)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.load_data()

        self.tree.setColumnWidth(0, 256)
        self.tree.setColumnWidth(1, 256)
        self.tree.setColumnWidth(2, 256)
        self.tree.setColumnWidth(3, 256)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        """Called when the plugin form is closed."""
        del self

    def Show(self):
        """Creates the form is not created or focuses it if it was."""
        return PluginForm.Show(self, 'ArmUnwind 0x%0.8x' % GetRegValue('PC'))


g_arm_unwinder = ArmUnwinder()


def get_unwinder():
    """exported api"""
    return g_arm_unwinder


def unwind_now(show_gui):
    """exported api"""
    if not is_debugger_on():
        warning("Please run script after attach target process.")
        return None
    if get_inf_structure().procName != "ARM":
        warning("This plugin only supports ARM32 CPU.")
        return None
    _pcs = get_unwinder().unwind_all()
    _frames = ArmUnwinder.pclist2framelist(_pcs)
    if show_gui:
        _view = ArmUnwindView(_frames)
        _view.Show()
    return _frames


def unwind_with_gui():
    """exported api"""
    return unwind_now(True)


def unwind_without_gui():
    """exported api"""
    return unwind_now(False)


ARM_UNWIND_HOTKEY = "Ctrl-Shift-U"


def unwind_add_hotkey(hotkey=ARM_UNWIND_HOTKEY):
    """exported api"""
    add_hotkey(hotkey, unwind_with_gui)


class ArmUnwindPlugin(plugin_t):
    """Class that is required for the code to be recognized as
    a plugin by IDA."""
    flags = 0
    comment = "arm unwind plugin"
    help = comment
    wanted_name = "arm unwind plugin"
    wanted_hotkey = ARM_UNWIND_HOTKEY

    def init(self):
        print "ArmUnwindPlugin init success."
        return PLUGIN_OK

    def run(self, arg):
        unwind_with_gui()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ArmUnwindPlugin()
