import string
import struct
import hashlib
from capstone import *
from capstone.x86 import *

ASCII = 1
WIDECHAR = 2
MAX_INSTRU = 0xfff
BCC = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",  "jge", "jb", "jbe", "ja", "jae", "jcxz",
       "jecxz", "jrcxz", "loop", "loopne", "loope", "call", "lcall"]
END = ["ret", "retn", "retf", "iret", "int3"]
BNC = ["jmp", "jmpf", "ljmp"]
CALL = ["call", "lcall"]


class CapsTool:
    """
    A class for storing the data to be disassembled.
    """
    def __init__(self, data, bit=32):
        self.data = data
        self.last_error = None
        self.pe_data = None
        self.MAX_BYTE_SIZE = 15
        self.BADADDR = 0xffffffffffffffff
        self.bit = bit
        if self.bit == 32:
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self._prev_addr_displacement = self.BADADDR
        self._is_pe() # this is kind of junk. TODO: revist

    class BLOCK(object):
        def __init__(self):
            self.start_ea = None  # start of the basic block
            self.end_ea = None  # end of the basic block
            self.id = None  # id of the basic block
            self.preds = None  # basic blocks that might execute before reaching this basic block.
            self.succs = None  # basic blocks that might execute after current basic block.

    class FUNCTION(object):
        def __init__(self):
            self.start_ea = None
            self.end_ea = None
            self.size = None
            self.id = None

        def find_prologue(self):
            pass

        def find_epilogue(self):
            pass

    def _is_pe(self):
        """

        :return:
        """
        if self.data[:2] == b"MZ":
            import pefile
            try:
                self.pe = pefile.PE(data=self.data)
                # read .text section into data
                self.pe_data = self.data
                for index, section in enumerate(self.pe.sections):
                    if b".text\x00" in section.Name or b".code\x00" in section.Name:
                        self.data = self.pe.sections[index].get_data()
                        self.sect_va = self.pe.sections[index].VirtualAddress
            except Exception as e:
                self.last_error = e
        else:
            self.pe = None

    def get_false_key(self, addr_bcc):
        """
        returns branch condition operand that has not been analyzed
        helper function
        :param addr_bcc: dict of {addr:True|False}
        :return:
        """
        for key in addr_bcc:
            if addr_bcc[key] is False:
                return True, key
        return False, None

    def to_signed_32(self, n):
        """
        converts unsigned to signed 32bit int
        :param n: unsigned 32 bit integer
        :return:
        """
        n = n & 0xffffffff
        return (n ^ 0x80000000) - 0x80000000

    def to_signed_64(self, n):
        """
        converts unsigned to signed 64bit int
        :param n: unsigned 64bit integer
        :return:
        """
        n = n & 0xffffffffffffffff
        return (n ^ 0x8000000000000000) - 0x8000000000000000

    def get_op_dist(self, bit, addr):
        """
        returns operand dist as signed int
        :param bit:
        :param addr:
        :return:
        """
        opp = self.get_operand_value(addr, 0)
        # check if operand is a register or some other non-int value
        op_dist  = None
        if not isinstance(opp, int):
            return False, op_dist
        # convert to unsigned int based off of bit
        elif bit == 32:
            op_dist = self.to_signed_32(opp)
        elif bit == 64:
            op_dist = self.to_signed_64(opp)
        return True, op_dist

    def dis_addr(self, addr, bit, debug=False):
        """
        returns addresses of instructions dism with recursive descent
        :param addr: address to start
        :param bit: 32bit or 64bit
        :param debug: print debug information
        :return: list of unsorted addresses
        """
        visited = []
        addr_bcc = {}
        while True:
            if len(visited) > MAX_INSTRU:
                break
            try:
                instr = self.get_mnem(addr)
            except Exception as e:
                print(e)
                break
            if debug:
                print(hex(addr), instr, addr_bcc) # , [hex(x) for x in visited]
            if addr in addr_bcc:
                if addr_bcc[addr] is False:
                    addr_bcc[addr] = True
                else:
                    status, t_addr = self.get_false_key(addr_bcc)
                    if status:
                        addr = t_addr
                        continue
                    else:
                        break
            if instr is None or self.dword(addr) == 0x0:
                status, t_addr = self.get_false_key(addr_bcc)
                if status:
                    addr = t_addr
                    continue
                else:
                    break
            if addr not in visited:
                visited.append(addr)
            if instr in BNC:
                status, op_dist = self.get_op_dist(bit, addr)
                if status:
                    addr = addr + op_dist
                    if addr in visited:
                        if addr in addr_bcc:
                            if addr_bcc[addr] is False:
                                addr_bcc[addr] = True
                        else:
                            addr_bcc[addr] = False
                        status, t_addr = self.get_false_key(addr_bcc)
                        if status:
                            addr = t_addr
                            continue

            elif instr in BCC:
                if self.word(addr) != 0x15ff:
                    status, op_dist = self.get_op_dist(bit, addr)
                    if status:
                        cal_addr = addr + op_dist
                        if cal_addr not in addr_bcc:
                            if cal_addr not in visited:
                                addr_bcc[cal_addr] = False
                        if self.byte(cal_addr - 1) == 0x00:
                            temp_data = self.get_many_bytes(addr + 5, op_dist - 6)
                            if temp_data:
                                if all(c in string.printable for c in temp_data):
                                    status, t_addr = self.get_false_key(addr_bcc)
                                    if status:
                                        addr = t_addr
                                        continue
            elif instr in END:
                status, t_addr = self.get_false_key(addr_bcc)
                if status:
                    addr = t_addr
                    continue
                else:
                    break
            addr = self.next_head(addr)
        return visited

    def flowchart(self, func):
        """

        :param func:
        :return:
        """
        blocks = []
        pass

    def get_basic_blocks(self, start, end, base=0, debug=False):
        """

        :param start:
        :param end:
        :return:
        """
        # TODO add more attributes to the loop (e.g. dominators, etc)
        leaders = set([])
        leaders.add(start)
        basic_blocks = []
        curr_addr = start
        visited = []
        while curr_addr < end:
            visited.append(curr_addr)
            # ensure infinite loop doesn't occur
            if len(visited) > MAX_INSTRU:
                return None
            try:
                instr = self.get_mnem(curr_addr)
            except Exception as e:
                print("ERROR: Accessing mnemonic for basic block: %s" % e)
                break
            # is mnemonic branch non-conditional or conditional
            if (instr in BNC or instr in BCC) and instr not in CALL:
                target_addr = self.get_operand_value(curr_addr, 0)
                # skip instructions in which the branch successor is a register (eax)
                if isinstance(target_addr, str):
                    curr_addr = self.next_head(curr_addr)
                    continue
                if debug:
                    print("0x%x, %s, 0x%x" % (curr_addr, self.get_disasm(curr_addr), target_addr))
                leaders.add(target_addr)
                temp_addr = self.next_head(curr_addr)
                if temp_addr is not None or temp_addr < end:
                    leaders.add(self.next_head(curr_addr))
            elif instr in END:
                prev = self.prev_head(curr_addr)
                prev_inst = self.get_mnem(prev)

                """
                This logic handles the following use case 
                004010cf  b800000000         mov     eax, 0x0
                004010d4  4885c0             test    rax, rax
                004010d7  7407               je      0x4010e0

                004010d9  bf30404000         mov     edi, 0x404030
                004010de  ffe0               jmp     rax  
                004010e0  c3                 retn    
                """
                if prev_inst in BNC and self.get_operand_type(prev_inst, 0) == X86_OP_REG:
                    tt_next = self.next_head(curr_addr)
                    if tt_next != end:
                        leaders.add(curr_addr)
                        leaders.add(tt_next)

            # is mnemonic end instruction
            curr_addr = self.next_head(curr_addr)

        # calculate block boundaries
        leaders = sorted(leaders)
        print([hex(x+base) for x  in leaders])
        for ii, vv in enumerate(leaders[:-1]):
            try:
                tt = visited.index(leaders[ii+1])
                start = vv
                end = visited[tt]
            except:
                # TODO: revist this code looks like made up logic
                start = vv
                end = leaders[-1]
            block = {}
            block["start"] = start + base
            block["end"] = end + base
            block["id"] = ii
            basic_blocks.append(block)
        if debug:
            for ii in leaders:
                print(hex(ii))
        return basic_blocks


    def fo(self, value):
        """
        Convert virtual address to file on diskcd
        :param value: virtual address
        :return:
        """
        if isinstance(value, int) and self.pe:
            return self.pe.get_offset_from_rva(value - self.pe.OPTIONAL_HEADER.ImageBase)
        return None

    def get_operand_value(self, ea, n):
        """
        Get number used in the operand
        This function returns an immediate number used in the operand
        @param ea: linear address of instruction
        @param n: the operand number
        @return: value
        """
        for insn in self.md.disasm(self.data[ea:], ea, 1):
            if len(insn.operands) >= n:
                for c, i in enumerate(insn.operands):
                    if c == n:
                        if i.type == X86_OP_REG:
                            return insn.reg_name(i.reg)
                        if i.type == X86_OP_IMM:
                            return i.imm
                        if i.type == X86_OP_MEM:
                            if i.mem.segment != 0:
                                return insn.reg_name(i.mem.segment)
                            if i.mem.base != 0:
                                return insn.reg_name(i.mem.base)
                            if i.mem.index != 0:
                                return insn.reg_name(i.mem.index)
                            if i.mem.scale != 1:
                                return i.mem.scale
                            if i.mem.disp != 0:
                                return i.mem.disp

    def get_operand_type(self, ea, n):
        """
        Get type of instruction operand
        :param ea: linear address of instruction
        :param n:
        :return:
        """
        for insn in self.md.disasm(self.data[ea:], ea, 1):
            if len(insn.operands) >= n:
                for c, i in enumerate(insn.operands):
                    if c == n:
                        if i.type == X86_OP_REG:
                            return X86_OP_REG
                        if i.type == X86_OP_IMM:
                            return X86_OP_IMM
                        if i.type == X86_OP_MEM:
                            return X86_OP_MEM

    def get_input_sha256(self):
        """
        Return the sha256 hash of the input binary file
        @return: sha256 string or None on error
        """
        return hashlib.sha256(self.data).hexdigest()

    def get_input_md5(self):
        """
        Return the MD5 hash of the input binary file
        @return: MD5 string or None on error
        """
        return hashlib.md5(self.data).hexdigest()

    def get_many_bytes(self, ea, size):
        """
        Return the specified number of bytes of the program
        @param ea: linear address
        @param size: size of buffer in normal 8-bit bytes
        @return: None on failure
                 otherwise a string containing the read bytes
        """
        if self.pe:
            temp = self.pe_data[ea:ea+size]
        else:
            temp = self.data[ea:ea+size]
        if len(temp) == size:
            return temp
        else:
            return None

    def byte(self, ea):
        """
        Get value of program byte
        @param ea: linear address
        @return: value of byte. If byte has no value then returns 0xFF
            If the current byte size is different from 8 bits, then the returned value
            might have more 1's.
            To check if a byte has a value, use functions hasValue(GetFlags(ea))
        """
        try:
            return struct.unpack("<B", self.data[ea])[0]
        except:
            return None

    def word(self, ea):
        """
        Get value of program word (2 bytes)
        @param ea: linear address
        @return: the value of the word. If word has no value then returns 0xFFFF
            If the current byte size is different from 8 bits, then the returned value
            might have more 1's.
        """
        try:
            tmp = self.data[ea:ea+2]
            return struct.unpack("<H", tmp)[0]
        except:
            return None

    def dword(self, ea):
        """
        Get value of program double word (4 bytes)
        @param ea: linear address
        @return: the value of the double word. If failed returns -1
        """
        try:
            tmp = self.data[ea:ea+4]
            return struct.unpack("<I", tmp)[0]
        except:
            return None

    def qword(self, ea):
        """
        Get value of program quadro word (8 bytes)
        @param ea: linear address
        @return: the value of the quadro word. If failed, returns -1
        """
        try:
            tmp = self.data[ea:ea+8]
            return struct.unpack("<Q", tmp)[0]
        except:
            return None

    def get_float(self, ea):
        """
        Get value of a floating point number (4 bytes)
        This function assumes number stored using IEEE format
        and in the same endianness as integers.
        @param ea: linear address
        @return: float
        """
        try:
            tmp = struct.pack("I", self.Dword(ea))
            return struct.unpack("f", tmp)[0]
        except:
            return None

    def get_double(self, ea):
        """
        Get value of a floating point number (8 bytes)
        This function assumes number stored using IEEE format
        and in the same endianness as integers.
        @param ea: linear address
        @return: double
        """
        try:
            tmp = struct.pack("Q", self.Qword(ea))
            return struct.unpack("d", tmp)[0]
        except:
            return None

    def get_disasm(self, ea):
        """
        Get disassembly line
        @param ea: linear address of instruction
        @return: "" - could not decode instruction at the specified location
        @note: this function may not return exactly the same mnemonics
               as you see on the screen.
        """
        return self.get_disasm_ex(ea)

    def get_disasm_ex(self, ea, flags=0):
        """
        Get disassembly line
        @param ea: linear address of instruction
        @param flags: combination of the GENDSM_ flags, or 0
        @return: "" - could not decode instruction at the specified location
        @note: this function may not return exactly the same mnemonics
               as you see on the screen.
        """
        code = self.data[ea:ea + self.MAX_BYTE_SIZE]
        instru = ""
        for i in self.md.disasm(code, ea):
            instru = "%s %s" % (i.mnemonic, i.op_str)
            return instru
        else:
            return None

    def get_mnem(self, ea):
        """
        Get instruction mnemonics
        @param ea: linear address of instruction
        @return: "" - no instruction at the specified location
        @note: this function may not return exactly the same mnemonics
        as you see on the screen.
        """
        code = self.data[ea:ea + self.MAX_BYTE_SIZE]
        for (address, size, mnemonic, op_str) in self.md.disasm_lite(code, 0, 1):
            if mnemonic:
                return mnemonic
            else:
                return None

    def next_addr(self, ea):
        """
        Get next address in the program
        @param ea: linear address
        @return: BADADDR - the specified address in the last used address
        """
        addr = ea + 1
        if len(self.data) > addr > 0:
            return addr
        else:
            return self.BADADDR


    def prev_addr(self, ea):
        """
        Get previous address in the program
        @param ea: linear address
        @return: BADADDR - the specified address in the first address
        """
        addr = ea - 1
        if len(self.data) > addr > 0:
            return addr
        else:
            return self.BADADDR


    def next_head(self, ea):
        """
        Get next defined item (instruction or data) in the program
        @param ea: linear address to start search from
        @param maxea: the search will stop at the address
            maxea is not included in the search range
        @return: BADADDR - no (more) defined items
        """
        code = self.data[ea:ea + self.MAX_BYTE_SIZE]
        for (address, size, mnemonic, op_str) in self.md.disasm_lite(code, 0, 1):
            if size:
                return size + ea
            else:
                return self.BADADDR


    def prev_head(self, ea):
        """
        Get previous defined item (instruction or data) in the program
        @param ea: linear address to start search from
        @param minea: the search will stop at the address
                minea is included in the search range
        @return: BADADDR - no (more) defined items
        """
        # uses an anchor to start disassembling from, decently accurate
        self._start_heuristic(ea)
        if self._prev_addr_displacement is not self.BADADDR:
            return ea - self._prev_addr_displacement

        # backtrace byte by byte
        for offset in range(self.MAX_BYTE_SIZE, 0, -1):
            if ea - offset < 0:
                    continue
            # read 1 byte before ea, read 2 bytes before ea, read 3 bytes before ea, etc...
            code = self.data[ea - offset: ea]
            for (address, size, mnemonic, op_str) in self.md.disasm_lite(code, 0, 1):
                # if dism size is the next ea then return size.
                # this technique fails if the bytes contain memory addresses, for example
                # "mov dword ptr [0x40a2e0]" the addr 0x40a2e0 adds more complications
                if ea - offset + size == ea:
                    return ea - size
        return self.BADADDR

    def get_strlit_contents(self, ea, length=None, strtype=ASCII):
        """
        previously known as GetString, returns
        :param ea: address/offset to start reading from
        :param length: length of the string to read
        :param strtype: ASCII = 1 or WIDECHAR = 2
        :return: strings in ASCII format (even if unicode) IDA seems to do the same
        """
        if self.pe:
            temp_data = self.pe_data
        else:
            temp_data = self.data
        if length and strtype == WIDECHAR:
            return temp_data[ea:ea+length][::2]
        elif length and strtype == ASCII:
            temp = temp_data[ea:ea + length]
            return temp.split("\x00")[0]
        if strtype == ASCII:
            # rely on Python to return str
            temp = temp_data[ea:]
            return temp.split("\x00")[0]
        elif strtype == WIDECHAR:
            temp_data = temp_data[ea:].split(b"\x00\x00")[0]
            return temp_data[::2]

    def _start_heuristic(self, ea):
        """
        Assign displacement start of previous address by using commmon byte patterns as anchors
        :param ea:
        :return:
        """
        temp_data = self.data[:ea+self.MAX_BYTE_SIZE]
        func_pro = b"\x55\x8B\xEC"
        func_nop = b"\x90"
        offset = temp_data.find(func_pro)
        if offset == -1:
            offset = temp_data.find(func_nop)
            if offset == -1:
                return
        temp_buffer = temp_data[offset:ea+self.MAX_BYTE_SIZE]
        addr_list = []
        for (address, size, mnemonic, op_str) in self.md.disasm_lite(temp_buffer,0):
            addr_list.append(address)
        if (ea - offset) in addr_list:
            ea_addr_index = addr_list.index( ea - offset)
            displ = addr_list[ea_addr_index] - addr_list[ea_addr_index - 1]
            if displ >= 0:
                self._prev_addr_displacement = displ


# the below are functions that could be implemented or just a todo list.

# def GetFlags(ea):
    # """
    # Get internal flags
    # @param ea: linear address
    # @return: 32-bit value of internal flags. See start of IDC.IDC file
        # for explanations.
    # """
    # return ida_bytes.getFlags(ea)


# def IdbByte(ea):
    # """
    # Get one byte (8-bit) of the program at 'ea' from the database even if the debugger is active
    # @param ea: linear address
    # @return: byte value. If the byte has no value then 0xFF is returned.
    # @note: If the current byte size is different from 8 bits, then the returned value may have more 1's.
           # To check if a byte has a value, use this expr: hasValue(GetFlags(ea))
    # """
    # return ida_bytes.get_db_byte(ea)

# TODO: Add once db is done
# def LocByName(name):
    # """
    # Get linear address of a name
    # @param name: name of program byte
    # @return: address of the name
             # BADADDR - No such name
    # """
    # return ida_name.get_name_ea(BADADDR, name)

# TODO: Add once db is done
# def LocByNameEx(fromaddr, name):
    # """
    # Get linear address of a name
    # @param fromaddr: the referring address. Allows to retrieve local label
               # addresses in functions. If a local name is not found,
               # then address of a global name is returned.
    # @param name: name of program byte
    # @return: address of the name (BADADDR - no such name)
    # @note: Dummy names (like byte_xxxx where xxxx are hex digits) are parsed by this
           # function to obtain the address. The database is not consulted for them.
    # """
    # return ida_name.get_name_ea(fromaddr, name)

# TODO: Implement using pefile
# def SegByBase(base):
    # """
    # Get segment by segment base
    # @param base: segment base paragraph or selector
    # @return: linear address of the start of the segment or BADADDR
             # if no such segment
    # """
    # sel = ida_segment.find_selector(base)
    # seg = ida_segment.get_segm_by_sel(sel)

    # if seg:
        # return seg.startEA
    # else:
        # return BADADDR

# TODO: N/A
# def SelStart():
    # """
    # Get start address of the selected area
    # returns BADADDR - the user has not selected an area
    # """
    # selection, startaddr, endaddr = ida_kernwin.read_selection()

    # if selection == 1:
        # return startaddr
    # else:
        # return BADADDR

# TODO: N/A
# def SelEnd():
    # """
    # Get end address of the selected area
    # @return: BADADDR - the user has not selected an area
    # """
    # selection, startaddr, endaddr = ida_kernwin.read_selection()

    # if selection == 1:
        # return endaddr
    # else:
        # return BADADDR


# def GetReg(ea, reg):
    # """
    # Get value of segment register at the specified address
    # @param ea: linear address
    # @param reg: name of segment register
    # @return: the value of the segment register or -1 on error
    # @note: The segment registers in 32bit program usually contain selectors,
           # so to get paragraph pointed to by the segment register you need to
           # call AskSelector() function.
    # """
    # reg = ida_idp.str2reg(reg);
    # if reg >= 0:
        # return ida_srarea.getSR(ea, reg)
    # else:
        # return -1


# def NextNotTail(ea):
    # """
    # Get next not-tail address in the program
    # This function searches for the next displayable address in the program.
    # The tail bytes of instructions and data are not displayable.
    # @param ea: linear address
    # @return: BADADDR - no (more) not-tail addresses
    # """
    # return ida_bytes.next_not_tail(ea)


# def PrevNotTail(ea):
    # """
    # Get previous not-tail address in the program
    # This function searches for the previous displayable address in the program.
    # The tail bytes of instructions and data are not displayable.
    # @param ea: linear address
    # @return: BADADDR - no (more) not-tail addresses
    # """
    # return ida_bytes.prev_not_tail(ea)


# def ItemHead(ea):
    # """
    # Get starting address of the item (instruction or data)
    # @param ea: linear address
    # @return: the starting address of the item
             # if the current address is unexplored, returns 'ea'
    # """
    # return ida_bytes.get_item_head(ea)


# def ItemEnd(ea):
    # """
    # Get address of the end of the item (instruction or data)
    # @param ea: linear address
    # @return: address past end of the item at 'ea'
    # """
    # return ida_bytes.get_item_end(ea)


# def ItemSize(ea):
    # """
    # Get size of instruction or data item in bytes
    # @param ea: linear address
    # @return: 1..n
    # """
    # return ida_bytes.get_item_end(ea) - ea


# def NameEx(fromaddr, ea):
    # """
    # Get visible name of program byte
    # This function returns name of byte as it is displayed on the screen.
    # If a name contains illegal characters, IDA replaces them by the
    # substitution character during displaying. See IDA.CFG for the
    # definition of the substitution character.
    # @param fromaddr: the referring address. May be BADADDR.
               # Allows to retrieve local label addresses in functions.
               # If a local name is not found, then a global name is
               # returned.
    # @param ea: linear address
    # @return: "" - byte has no name
    # """
    # name = ida_name.get_name(fromaddr, ea)

    # if not name:
        # return ""
    # else:
        # return name


# def GetTrueNameEx(fromaddr, ea):
    # """
    # Get true name of program byte
    # This function returns name of byte as is without any replacements.
    # @param fromaddr: the referring address. May be BADADDR.
           # Allows to retrieve local label addresses in functions.
           # If a local name is not found, then a global name is returned.
    # @param ea: linear address
    # @return: "" - byte has no name
    # """
    # name = ida_name.get_true_name(fromaddr, ea)

    # if not name:
        # return ""
    # else:
        # return name


#
#     def GetOpType(self, ea, n):
#         """
#         Get type of instruction operand
#         @param ea: linear address of instruction
#         @param n: number of operand:
#             0 - the first operand
#             1 - the second operand
#         @return: any of o_* constants or -1 on error
#         """
#         self.capstone.detail = True
#         code = self.data[ea:ea + self.MAX_BYTE_SIZE]
#         for instru in self.capstone.disasm(code, 0, 1):
#             c = 0
#             for i in instru.operands:
#                 if n == c:
#                     return i.type
#         return None
#
#
# o_void     = ida_ua.o_void      # No Operand                           ----------
# o_reg      = ida_ua.o_reg       # General Register (al,ax,es,ds...)    reg
# o_mem      = ida_ua.o_mem       # Direct Memory Reference  (DATA)      addr
# o_phrase   = ida_ua.o_phrase    # Memory Ref [Base Reg + Index Reg]    phrase
# o_displ    = ida_ua.o_displ     # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
# o_imm      = ida_ua.o_imm       # Immediate Value                      value
# o_far      = ida_ua.o_far       # Immediate Far Address  (CODE)        addr
# o_near     = ida_ua.o_near      # Immediate Near Address (CODE)        addr
# o_idpspec0 = ida_ua.o_idpspec0  # Processor specific type
# o_idpspec1 = ida_ua.o_idpspec1  # Processor specific type
# o_idpspec2 = ida_ua.o_idpspec2  # Processor specific type
# o_idpspec3 = ida_ua.o_idpspec3  # Processor specific type
# o_idpspec4 = ida_ua.o_idpspec4  # Processor specific type
# o_idpspec5 = ida_ua.o_idpspec5  # Processor specific type
#                                 # There can be more processor specific types
#
# # x86
# o_trreg  =       ida_ua.o_idpspec0      # trace register
# o_dbreg  =       ida_ua.o_idpspec1      # debug register
# o_crreg  =       ida_ua.o_idpspec2      # control register
# o_fpreg  =       ida_ua.o_idpspec3      # floating point register
# o_mmxreg  =      ida_ua.o_idpspec4      # mmx register
# o_xmmreg  =      ida_ua.o_idpspec5      # xmm register
#
#
#
#     def GetOperandValue(self, ea, n):
#         """
#         Get number used in the operand
#         This function returns an immediate number used in the operand
#         @param ea: linear address of instruction
#         @param n: the operand number
#         @return: value
#             operand is an immediate value  => immediate value
#             operand has a displacement     => displacement
#             operand is a direct memory ref => memory address
#             operand is a register          => register number
#             operand is a register phrase   => phrase number
#             otherwise                      => -1
#         """
#         inslen = ida_ua.decode_insn(ea)
#         if inslen == 0:
#             return -1
#         op = ida_ua.cmd.Operands[n]
#         if not op:
#             return -1
#
#         if op.type in [ ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near, ida_ua.o_displ ]:
#             value = op.addr
#         elif op.type == ida_ua.o_reg:
#             value = op.reg
#         elif op.type == ida_ua.o_imm:
#             value = op.value
#         elif op.type == ida_ua.o_phrase:
#             value = op.phrase
#         else:
#             value = -1
#         return value
#
#
# def LineA(ea, num):
#     """
#     Get anterior line
#     @param ea: linear address
#     @param num: number of anterior line (0..MAX_ITEM_LINES)
#           MAX_ITEM_LINES is defined in IDA.CFG
#     @return: anterior line string
#     """
#     return ida_lines.get_extra_cmt(ea, ida_lines.E_PREV + num)
#
#
# def LineB(ea, num):
#     """
#     Get posterior line
#     @param ea: linear address
#     @param num: number of posterior line (0..MAX_ITEM_LINES)
#     @return: posterior line string
#     """
#     return ida_lines.get_extra_cmt(ea, ida_lines.E_NEXT + num)
#
#
# # def GetCommentEx(ea, repeatable):
#     # """
#     # Get regular indented comment
#     # @param ea: linear address
#     # @param repeatable: 1 to get the repeatable comment, 0 to get the normal comment
#     # @return: string or None if it fails
#     # """
#     # return ida_bytes.get_cmt(ea, repeatable)
#
#
# # def CommentEx(ea, repeatable):
#     # """
#     # Get regular indented comment
#     # @param ea: linear address
#     # @param repeatable: 1 to get the repeatable comment, 0 to get the normal comment
#     # @return: string or None if it fails
#     # """
#     # return GetCommentEx(ea, repeatable)
#
#
# # def AltOp(ea, n):
#     # """
#     # Get manually entered operand string
#     # @param ea: linear address
#     # @param n: number of operand:
#          # 0 - the first operand
#          # 1 - the second operand
#     # @return: string or None if it fails
#     # """
#     # return ida_bytes.get_forced_operand(ea, n)
#
# # ASCSTR_C       = ida_nalt.ASCSTR_TERMCHR # C-style ASCII string
# # ASCSTR_PASCAL  = ida_nalt.ASCSTR_PASCAL  # Pascal-style ASCII string (length byte)
# # ASCSTR_LEN2    = ida_nalt.ASCSTR_LEN2    # Pascal-style, length is 2 bytes
# # ASCSTR_UNICODE = ida_nalt.ASCSTR_UNICODE # Unicode string
# # ASCSTR_LEN4    = ida_nalt.ASCSTR_LEN4    # Pascal-style, length is 4 bytes
# # ASCSTR_ULEN2   = ida_nalt.ASCSTR_ULEN2   # Pascal-style Unicode, length is 2 bytes
# # ASCSTR_ULEN4   = ida_nalt.ASCSTR_ULEN4   # Pascal-style Unicode, length is 4 bytes
# # ASCSTR_LAST    = ida_nalt.ASCSTR_LAST    # Last string type
#
#  TODO: Completed
# # def GetString(ea, length = -1, strtype = ASCSTR_C):
#     # """
#     # Get string contents
#     # @param ea: linear address
#     # @param length: string length. -1 means to calculate the max string length
#     # @param strtype: the string type (one of ASCSTR_... constants)
#     # @return: string contents or empty string
#     # """
#     # if length == -1:
#         # length = ida_bytes.get_max_ascii_length(ea, strtype, ida_bytes.ALOPT_IGNHEADS)
#
#     # return ida_bytes.get_ascii_contents2(ea, length, strtype)
#
#
# # def GetStringType(ea):
#     # """
#     # Get string type
#     # @param ea: linear address
#     # @return: One of ASCSTR_... constants
#     # """
#     # ti = ida_nalt.opinfo_t()
#
#     # if ida_bytes.get_opinfo(ea, 0, GetFlags(ea), ti):
#         # return ti.strtype
#     # else:
#         # return None
#
# # #      The following functions search for the specified byte
# # #          ea - address to start from
# # #          flag is combination of the following bits
#
# # #      returns BADADDR - not found
# # def FindVoid        (ea, flag): return ida_search.find_void(ea, flag)
# # def FindCode        (ea, flag): return ida_search.find_code(ea, flag)
# # def FindData        (ea, flag): return ida_search.find_data(ea, flag)
# # def FindUnexplored  (ea, flag): return ida_search.find_unknown(ea, flag)
# # def FindExplored    (ea, flag): return ida_search.find_defined(ea, flag)
# # def FindImmediate   (ea, flag, value): return ida_search.find_imm(ea, flag, value)
#
# # SEARCH_UP       = ida_search.SEARCH_UP       # search backward
# # SEARCH_DOWN     = ida_search.SEARCH_DOWN     # search forward
# # SEARCH_NEXT     = ida_search.SEARCH_NEXT     # start the search at the next/prev item
#                                              # # useful only for FindText() and FindBinary()
# # SEARCH_CASE     = ida_search.SEARCH_CASE     # search case-sensitive
#                                              # # (only for bin&txt search)
# # SEARCH_REGEX    = ida_search.SEARCH_REGEX    # enable regular expressions (only for text)
# # SEARCH_NOBRK    = ida_search.SEARCH_NOBRK    # don't test ctrl-break
# # SEARCH_NOSHOW   = ida_search.SEARCH_NOSHOW   # don't display the search progress
#
# def FindText(ea, flag, y, x, searchstr):
#     """
#     @param ea: start address
#     @param flag: combination of SEARCH_* flags
#     @param y: number of text line at ea to start from (0..MAX_ITEM_LINES)
#     @param x: coordinate in this line
#     @param searchstr: search string
#     @return: ea of result or BADADDR if not found
#     """
#     return ida_search.find_text(ea, y, x, searchstr, flag)
#
#
# def FindBinary(ea, flag, searchstr, radix=16):
#     """
#     @param ea: start address
#     @param flag: combination of SEARCH_* flags
#     @param searchstr: a string as a user enters it for Search Text in Core
#     @param radix: radix of the numbers (default=16)
#     @return: ea of result or BADADDR if not found
#     @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)
#     """
#     endea = flag & 1 and ida_ida.cvar.inf.maxEA or ida_ida.cvar.inf.minEA
#     return ida_search.find_binary(ea, endea, searchstr, radix, flag)
#
#
# #----------------------------------------------------------------------------
# #                    C R O S S   R E F E R E N C E S
# #----------------------------------------------------------------------------
# #      Flow types (combine with XREF_USER!):
# fl_CF   = 16              # Call Far
# fl_CN   = 17              # Call Near
# fl_JF   = 18              # Jump Far
# fl_JN   = 19              # Jump Near
# fl_F    = 21              # Ordinary flow
#
# XREF_USER = 32            # All user-specified xref types
#                           # must be combined with this bit
#
#
# # Mark exec flow 'from' 'to'
# def AddCodeXref(From, To, flowtype):
#     """
#     """
#     return ida_xref.add_cref(From, To, flowtype)
#
#
# def DelCodeXref(From, To, undef):
#     """
#     Unmark exec flow 'from' 'to'
#     @param undef: make 'To' undefined if no more references to it
#     @returns: 1 - planned to be made undefined
#     """
#     return ida_xref.del_cref(From, To, undef)
#
#
# # The following functions include the ordinary flows:
# # (the ordinary flow references are returned first)
# def Rfirst(From):
#     """
#     Get first code xref from 'From'
#     """
#     return ida_xref.get_first_cref_from(From)
#
#
# def Rnext(From, current):
#     """
#     Get next code xref from
#     """
#     return ida_xref.get_next_cref_from(From, current)
#
#
# def RfirstB(To):
#     """
#     Get first code xref to 'To'
#     """
#     return ida_xref.get_first_cref_to(To)
#
#
# def RnextB(To, current):
#     """
#     Get next code xref to 'To'
#     """
#     return ida_xref.get_next_cref_to(To, current)
#
#
# # The following functions don't take into account the ordinary flows:
# def Rfirst0(From):
#     """
#     Get first xref from 'From'
#     """
#     return ida_xref.get_first_fcref_from(From)
#
#
# def Rnext0(From, current):
#     """
#     Get next xref from
#     """
#     return ida_xref.get_next_fcref_from(From, current)
#
#
# def RfirstB0(To):
#     """
#     Get first xref to 'To'
#     """
#     return ida_xref.get_first_fcref_to(To)
#
#
# def RnextB0(To, current):
#     """
#     Get next xref to 'To'
#     """
#     return ida_xref.get_next_fcref_to(To, current)
#
#
# # Data reference types (combine with XREF_USER!):
# dr_O    = ida_xref.dr_O  # Offset
# dr_W    = ida_xref.dr_W  # Write
# dr_R    = ida_xref.dr_R  # Read
# dr_T    = ida_xref.dr_T  # Text (names in manual operands)
# dr_I    = ida_xref.dr_I  # Informational
#
#
# def add_dref(From, To, drefType):
#     """
#     Create Data Ref
#     """
#     return ida_xref.add_dref(From, To, drefType)
#
#
# def del_dref(From, To):
#     """
#     Unmark Data Ref
#     """
#     return ida_xref.del_dref(From, To)
#
#
# def Dfirst(From):
#     """
#     Get first data xref from 'From'
#     """
#     return ida_xref.get_first_dref_from(From)
#
#
# def Dnext(From, current):
#     """
#     Get next data xref from 'From'
#     """
#     return ida_xref.get_next_dref_from(From, current)
#
#
# def DfirstB(To):
#     """
#     Get first data xref to 'To'
#     """
#     return ida_xref.get_first_dref_to(To)
#
#
# def DnextB(To, current):
#     """
#     Get next data xref to 'To'
#     """
#     return ida_xref.get_next_dref_to(To, current)
#
#
# def XrefType():
#     """
#     Return type of the last xref obtained by
#     [RD]first/next[B0] functions.
#     @return: constants fl_* or dr_*
#     """
# raise DeprecatedIDCError, "use XrefsFrom() XrefsTo() from idautils instead."
#