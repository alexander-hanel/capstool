import string
import struct
import hashlib
import bisect
import re
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
COND_BRANCH = [item for item in BCC if item not in CALL]
KNOWN_NORETURN_IMPORTS = {
    "ExitProcess",
    "TerminateProcess",
    "abort",
    "_abort",
    "_exit",
    "exit",
    "FatalExit",
    "__report_gsfailure",
    "_amsg_exit",
    "_invalid_parameter_noinfo_noreturn",
    "_invoke_watson",
    "RaiseFailFastException",
}


class CapsTool:
    """
    A class for storing the data to be disassembled.
    """
    def __init__(self, data, bit=32):
        self.data = data
        self.last_error = None
        self.pe_data = None
        self.pe = None
        self.image_base = 0
        self.entry_rva = None
        self.sect_va = 0
        self.sect_raw = 0
        self.code_section_name = None
        self.MAX_BYTE_SIZE = 15
        self.BADADDR = 0xffffffffffffffff
        self.bit = bit
        if self.bit == 32:
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self._prev_addr_displacement = self.BADADDR
        self._functions_cache = {}
        self._building_functions = False
        self._recovered_prev_head_cache = None
        self._recovered_instruction_starts_cache = None
        self._strings_cache = None
        self._string_lookup = None
        self._label_cache = {}
        self._user_labels = {}
        self._comments = {
            False: {},
            True: {},
        }
        self._function_comments = {
            False: {},
            True: {},
        }
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
                self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
                self.entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                # read .text section into data
                self.pe_data = self.data
                for index, section in enumerate(self.pe.sections):
                    if b".text\x00" in section.Name or b".code\x00" in section.Name:
                        self.data = self.pe.sections[index].get_data()
                        self.sect_va = self.pe.sections[index].VirtualAddress
                        self.sect_raw = self.pe.sections[index].PointerToRawData
                        self.code_section_name = self.pe.sections[index].Name.rstrip(b"\x00").decode("ascii", errors="ignore")
                        break
            except Exception as e:
                self.pe = None
                self.last_error = e

    def _is_analysis_offset(self, value):
        """
        Return True when value is a valid section-relative analysis offset.
        :param value:
        :return:
        """
        return isinstance(value, int) and 0 <= value < len(self.data)

    def _get_binary_data(self):
        """
        Return the original input bytes when available.
        :return:
        """
        if self.pe_data is not None:
            return self.pe_data
        return self.data

    def _get_binary_length(self):
        """
        Return the total input length.
        :return:
        """
        return len(self._get_binary_data())

    def analysis_offset_to_rva(self, value):
        """
        Convert section-relative analysis offset to RVA.
        :param value:
        :return:
        """
        if self._is_analysis_offset(value):
            if self.pe:
                return self.sect_va + value
            return value
        return None

    def analysis_offset_to_va(self, value):
        """
        Convert section-relative analysis offset to VA.
        :param value:
        :return:
        """
        rva = self.analysis_offset_to_rva(value)
        if rva is None:
            return None
        if self.pe:
            return self.image_base + rva
        return rva

    def analysis_offset_to_file_offset(self, value):
        """
        Convert section-relative analysis offset to file offset.
        :param value:
        :return:
        """
        if self._is_analysis_offset(value):
            if self.pe:
                return self.sect_raw + value
            return value
        return None

    def rva_to_analysis_offset(self, value):
        """
        Convert RVA to section-relative analysis offset.
        :param value:
        :return:
        """
        if not isinstance(value, int):
            return None
        if self.pe:
            analysis_offset = value - self.sect_va
            if self._is_analysis_offset(analysis_offset):
                return analysis_offset
            return None
        if self._is_analysis_offset(value):
            return value
        return None

    def va_to_analysis_offset(self, value):
        """
        Convert VA to section-relative analysis offset.
        :param value:
        :return:
        """
        if not isinstance(value, int):
            return None
        if self.pe:
            return self.rva_to_analysis_offset(value - self.image_base)
        return self.rva_to_analysis_offset(value)

    def _format_import_label(self, dll_name, import_name, ordinal):
        """
        Format an imported symbol label.
        :param dll_name:
        :param import_name:
        :param ordinal:
        :return:
        """
        symbol_name = import_name if import_name else "ordinal_%s" % ordinal
        if dll_name:
            return "%s!%s" % (dll_name, symbol_name)
        return symbol_name

    def _normalize_repeatable(self, repeatable):
        """
        Normalize an IDA-style repeatable flag to bool.
        :param repeatable:
        :return:
        """
        return bool(repeatable)

    def _normalize_function_start(self, func):
        """
        Normalize a function-like input to a recovered function start.
        :param func:
        :return:
        """
        function = self._normalize_function(func)
        if function:
            return function["start_ea"]
        if isinstance(func, int) and self._is_direct_target(func):
            return func
        return None

    def _normalize_label_key(self, value, kind="analysis"):
        """
        Normalize an address-like value into a canonical label key.
        :param value:
        :param kind:
        :return:
        """
        address_info = self.get_binary_address_info(value, kind=kind)
        if not address_info:
            return None
        if address_info["analysis_offset"] is not None:
            return ("analysis", address_info["analysis_offset"])
        if address_info["va"] is not None:
            return ("va", address_info["va"])
        if address_info["file_offset"] is not None:
            return ("file", address_info["file_offset"])
        return None

    def _set_comment_value(self, store, key, comment):
        """
        Store or clear a comment string.
        :param store:
        :param key:
        :param comment:
        :return:
        """
        if key is None:
            return False
        if comment is None or comment == "":
            store.pop(key, None)
            return True
        store[key] = str(comment)
        return True

    def _get_repeatable_chain_comment(self, ea):
        """
        Return the nearest function-level repeatable comment for an address.
        :param ea:
        :return:
        """
        if self._building_functions:
            return None
        function = self.get_function(ea)
        if not function:
            return None
        return self._function_comments[True].get(function["start_ea"])

    def set_comment(self, ea, comment, repeatable=False):
        """
        Set or clear an instruction/data comment.
        :param ea:
        :param comment:
        :param repeatable:
        :return:
        """
        if not self._is_direct_target(ea):
            return False
        return self._set_comment_value(self._comments[self._normalize_repeatable(repeatable)], ea, comment)

    def get_comment(self, ea, repeatable=False):
        """
        Get an instruction/data comment.
        :param ea:
        :param repeatable:
        :return:
        """
        if not self._is_direct_target(ea):
            return ""
        repeatable = self._normalize_repeatable(repeatable)
        comment = self._comments[repeatable].get(ea)
        if comment:
            return comment
        if repeatable:
            function_comment = self._get_repeatable_chain_comment(ea)
            if function_comment:
                return function_comment
        return ""

    def get_comment_ex(self, ea, repeatable):
        """
        Snake-case comment getter compatible with IDA-style semantics.
        :param ea:
        :param repeatable:
        :return:
        """
        return self.get_comment(ea, repeatable=repeatable)

    def comment_ex(self, ea, repeatable=0, comment=None):
        """
        Snake-case compatibility helper for comment access.
        When comment is omitted, returns the comment text.
        When comment is provided, sets or clears the comment and returns success.
        :param ea:
        :param repeatable:
        :param comment:
        :return:
        """
        if comment is None:
            return self.get_comment(ea, repeatable=repeatable)
        return self.set_comment(ea, comment, repeatable=repeatable)

    def set_function_comment(self, func, comment, repeatable=False):
        """
        Set or clear a function comment.
        :param func:
        :param comment:
        :param repeatable:
        :return:
        """
        start_ea = self._normalize_function_start(func)
        if start_ea is None:
            return False
        return self._set_comment_value(self._function_comments[self._normalize_repeatable(repeatable)], start_ea, comment)

    def get_function_comment(self, func, repeatable=False):
        """
        Get a function comment.
        :param func:
        :param repeatable:
        :return:
        """
        start_ea = self._normalize_function_start(func)
        if start_ea is None:
            return ""
        return self._function_comments[self._normalize_repeatable(repeatable)].get(start_ea, "")

    def _get_import_lookup(self):
        """
        Return a VA to import-label lookup table for PE inputs.
        :return:
        """
        if hasattr(self, "_import_lookup"):
            return self._import_lookup
        self._import_lookup = {}
        if not self.pe or not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return self._import_lookup
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("ascii", errors="ignore") if entry.dll else None
            for imp in entry.imports:
                label = self._format_import_label(
                    dll_name,
                    imp.name.decode("ascii", errors="ignore") if imp.name else None,
                    imp.ordinal,
                )
                self._import_lookup[imp.address] = label
        return self._import_lookup

    def set_label(self, value, label, kind="analysis"):
        """
        Set or clear a user-defined label for an address-like value.
        :param value:
        :param label:
        :param kind:
        :return:
        """
        key = self._normalize_label_key(value, kind=kind)
        if key is None:
            return False
        if label is None or label == "":
            self._user_labels.pop(key, None)
            self._label_cache = {}
            return True
        self._user_labels[key] = str(label)
        self._label_cache = {}
        return True

    def get_label(self, value, kind="analysis"):
        """
        Return a user-defined label for an address-like value.
        :param value:
        :param kind:
        :return:
        """
        key = self._normalize_label_key(value, kind=kind)
        if key is None:
            return None
        return self._user_labels.get(key)

    def get_symbols(self, include_auto=False):
        """
        Return known symbols for the binary.
        :param include_auto:
        :return:
        """
        symbols = []
        for (kind, value), label in sorted(self._user_labels.items(), key=lambda item: (item[0][0], item[0][1])):
            info = self.get_binary_address_info(value, kind=kind)
            symbols.append({
                "kind": "user",
                "label": label,
                "address": info,
            })
        if include_auto:
            for function in self.find_functions():
                symbols.append({
                    "kind": "function",
                    "label": function.get("label"),
                    "address": self.get_address_info(function["start_ea"]),
                })
            for entry in self.find_strings():
                symbols.append({
                    "kind": "string",
                    "label": entry["label"],
                    "address": self.get_binary_address_info(entry["file_offset"], kind="file"),
                })
        return symbols

    def _lookup_import_label(self, va):
        """
        Resolve an import label from a VA.
        :param va:
        :return:
        """
        if not isinstance(va, int):
            return None
        return self._get_import_lookup().get(va)

    def rva_to_file_offset(self, value):
        """
        Convert RVA to file offset.
        :param value:
        :return:
        """
        if not isinstance(value, int):
            return None
        if self.pe:
            try:
                return self.pe.get_offset_from_rva(value)
            except Exception:
                return None
        return value

    def file_offset_to_rva(self, value):
        """
        Convert file offset to RVA.
        :param value:
        :return:
        """
        if not isinstance(value, int):
            return None
        if self.pe:
            try:
                return self.pe.get_rva_from_offset(value)
            except Exception:
                return None
        return value

    def va_to_file_offset(self, value):
        """
        Convert VA to file offset.
        :param value:
        :return:
        """
        if not isinstance(value, int):
            return None
        if self.pe:
            return self.rva_to_file_offset(value - self.image_base)
        return value

    def file_offset_to_va(self, value):
        """
        Convert file offset to VA.
        :param value:
        :return:
        """
        rva = self.file_offset_to_rva(value)
        if rva is None:
            return None
        if self.pe:
            return self.image_base + rva
        return rva

    def get_address_info(self, value, kind="analysis"):
        """
        Return normalized address information for an analysis/RVA/VA/file offset.
        :param value:
        :param kind:
        :return:
        """
        info = self.get_binary_address_info(value, kind=kind)
        if info is None or info["analysis_offset"] is None:
            return None
        return {
            "analysis_offset": info["analysis_offset"],
            "rva": info["rva"],
            "va": info["va"],
            "file_offset": info["file_offset"],
        }

    def _get_section_name_for_rva(self, rva):
        """
        Return the PE section name containing an RVA when available.
        :param rva:
        :return:
        """
        if not self.pe or not isinstance(rva, int):
            return None
        for section in self.pe.sections:
            start_rva = section.VirtualAddress
            section_size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if start_rva <= rva < (start_rva + section_size):
                return section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
        return None

    def get_binary_address_info(self, value, kind="analysis"):
        """
        Return normalized address information for any location in the input image.
        :param value:
        :param kind:
        :return:
        """
        if not isinstance(value, int):
            return None
        analysis_offset = None
        rva = None
        va = None
        file_offset = None
        binary_length = self._get_binary_length()
        if kind == "analysis":
            if not self._is_analysis_offset(value):
                return None
            analysis_offset = value
            rva = self.analysis_offset_to_rva(value)
            va = self.analysis_offset_to_va(value)
            file_offset = self.analysis_offset_to_file_offset(value)
        elif kind == "rva":
            if self.pe:
                rva = value
                file_offset = self.rva_to_file_offset(value)
                if file_offset is None:
                    return None
                va = self.image_base + value
                analysis_offset = self.rva_to_analysis_offset(value)
            elif 0 <= value < binary_length:
                analysis_offset = value
                rva = value
                va = value
                file_offset = value
            else:
                return None
        elif kind == "va":
            if self.pe:
                rva = value - self.image_base
                file_offset = self.rva_to_file_offset(rva)
                if file_offset is None:
                    return None
                va = value
                analysis_offset = self.va_to_analysis_offset(value)
            elif 0 <= value < binary_length:
                analysis_offset = value
                rva = value
                va = value
                file_offset = value
            else:
                return None
        elif kind == "file":
            if not (0 <= value < binary_length):
                return None
            file_offset = value
            if self.pe:
                rva = self.file_offset_to_rva(value)
                if rva is None:
                    return None
                va = self.image_base + rva
                analysis_offset = self.rva_to_analysis_offset(rva)
            else:
                analysis_offset = value
                rva = value
                va = value
        else:
            return None
        return {
            "analysis_offset": analysis_offset,
            "rva": rva,
            "va": va,
            "file_offset": file_offset,
            "section": self._get_section_name_for_rva(rva),
        }

    def get_sections(self):
        """
        Return section metadata for PE inputs.
        :return:
        """
        if not self.pe:
            return []
        sections = []
        for section in self.pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            start_rva = section.VirtualAddress
            virtual_size = section.Misc_VirtualSize
            end_rva = start_rva + max(virtual_size, section.SizeOfRawData)
            sections.append({
                "name": name,
                "virtual_address": start_rva,
                "virtual_size": virtual_size,
                "raw_size": section.SizeOfRawData,
                "file_offset": section.PointerToRawData,
                "characteristics": section.Characteristics,
                "contains_entry_point": start_rva <= self.entry_rva < end_rva if self.entry_rva is not None else False,
                "is_code_section": start_rva == self.sect_va,
            })
        return sections

    def get_entry_point(self):
        """
        Return entry point metadata.
        :return:
        """
        if self.pe:
            return {
                "rva": self.entry_rva,
                "va": self.image_base + self.entry_rva if self.entry_rva is not None else None,
                "file_offset": self.rva_to_file_offset(self.entry_rva),
                "analysis_offset": self.rva_to_analysis_offset(self.entry_rva),
            }
        if self._decode_insn(0):
            return {
                "rva": 0,
                "va": 0,
                "file_offset": 0,
                "analysis_offset": 0,
            }
        return None

    def get_imports(self):
        """
        Return imported symbols for PE inputs.
        :return:
        """
        if not self.pe or not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return []
        imports = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("ascii", errors="ignore") if entry.dll else None
            for imp in entry.imports:
                imports.append({
                    "dll": dll_name,
                    "name": imp.name.decode("ascii", errors="ignore") if imp.name else None,
                    "ordinal": imp.ordinal,
                    "address": imp.address,
                })
        return imports

    def get_exports(self):
        """
        Return exported symbols for PE inputs.
        :return:
        """
        if not self.pe or not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            return []
        exports = []
        for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "name": symbol.name.decode("ascii", errors="ignore") if symbol.name else None,
                "ordinal": symbol.ordinal,
                "rva": symbol.address,
                "va": self.image_base + symbol.address,
                "file_offset": self.rva_to_file_offset(symbol.address),
            })
        return exports

    def get_pe_metadata(self):
        """
        Return high-level PE metadata.
        :return:
        """
        if not self.pe:
            return None
        return {
            "image_base": self.image_base,
            "entry_point": self.get_entry_point(),
            "machine": self.pe.FILE_HEADER.Machine,
            "number_of_sections": self.pe.FILE_HEADER.NumberOfSections,
            "code_section": self.code_section_name,
            "sections": self.get_sections(),
            "imports": self.get_imports(),
            "exports": self.get_exports(),
        }

    def _is_ascii_string_byte(self, value):
        """
        Return True when a byte is printable ASCII for string recovery.
        :param value:
        :return:
        """
        return 0x20 <= value <= 0x7e or value in (0x09,)

    def _sanitize_label_component(self, text, max_length=40):
        """
        Convert free-form text into a label-safe component.
        :param text:
        :param max_length:
        :return:
        """
        if not text:
            return ""
        cleaned = re.sub(r"[^0-9A-Za-z_]+", "_", text)
        cleaned = re.sub(r"_+", "_", cleaned).strip("_")
        if not cleaned:
            return ""
        if cleaned[0].isdigit():
            cleaned = "s_" + cleaned
        return cleaned[:max_length]

    def _make_auto_string_label(self, text, address_info):
        """
        Build an IDA-like auto label for a recovered string.
        :param text:
        :param address_info:
        :return:
        """
        cleaned = self._sanitize_label_component(text)
        if cleaned:
            return "a%s" % cleaned
        anchor = address_info["va"] if address_info["va"] is not None else address_info["file_offset"]
        return "str_%x" % anchor

    def _build_string_entry(self, file_offset, raw_bytes, encoding, is_terminated):
        """
        Build a normalized string entry from raw bytes.
        :param file_offset:
        :param raw_bytes:
        :param encoding:
        :param is_terminated:
        :return:
        """
        if encoding == "utf16le":
            text = raw_bytes.decode("utf-16le", errors="ignore")
        else:
            text = raw_bytes.decode("ascii", errors="ignore")
        if not text:
            return None
        address_info = self.get_binary_address_info(file_offset, kind="file")
        if not address_info:
            return None
        entry = {
            "string": text,
            "encoding": encoding,
            "length": len(text),
            "is_terminated": is_terminated,
            "analysis_offset": address_info["analysis_offset"],
            "rva": address_info["rva"],
            "va": address_info["va"],
            "file_offset": address_info["file_offset"],
            "section": address_info["section"],
            "bytes": raw_bytes,
            "bytes_hex": raw_bytes.hex(),
        }
        entry["label"] = self._make_auto_string_label(text, address_info)
        return entry

    def _scan_ascii_strings(self, data, min_length=4):
        """
        Recover ASCII strings from the full input bytes.
        :param data:
        :param min_length:
        :return:
        """
        strings_found = []
        index = 0
        data_len = len(data)
        while index < data_len:
            start = index
            while index < data_len and self._is_ascii_string_byte(data[index]):
                index += 1
            if (index - start) >= min_length:
                is_terminated = index < data_len and data[index] == 0
                entry = self._build_string_entry(start, data[start:index], "ascii", is_terminated)
                if entry:
                    strings_found.append(entry)
            if index == start:
                index += 1
            else:
                while index < data_len and data[index] == 0:
                    index += 1
        return strings_found

    def _scan_wide_strings(self, data, min_length=4):
        """
        Recover UTF-16LE strings from the full input bytes.
        :param data:
        :param min_length:
        :return:
        """
        strings_found = []
        index = 0
        data_len = len(data)
        while index + 1 < data_len:
            start = index
            raw = bytearray()
            while index + 1 < data_len and self._is_ascii_string_byte(data[index]) and data[index + 1] == 0:
                raw.extend(data[index:index + 2])
                index += 2
            if len(raw) >= (min_length * 2):
                is_terminated = index + 1 < data_len and data[index:index + 2] == b"\x00\x00"
                entry = self._build_string_entry(start, bytes(raw), "utf16le", is_terminated)
                if entry:
                    strings_found.append(entry)
            if index == start:
                index += 1
            else:
                while index + 1 < data_len and data[index:index + 2] == b"\x00\x00":
                    index += 2
        return strings_found

    def _build_string_lookup(self):
        """
        Build fast address lookups for recovered strings.
        :return:
        """
        lookup = {
            "analysis": {},
            "rva": {},
            "va": {},
            "file": {},
        }
        for entry in self.find_strings():
            if entry["analysis_offset"] is not None:
                lookup["analysis"][entry["analysis_offset"]] = entry
            if entry["rva"] is not None:
                lookup["rva"][entry["rva"]] = entry
            if entry["va"] is not None:
                lookup["va"][entry["va"]] = entry
            if entry["file_offset"] is not None:
                lookup["file"][entry["file_offset"]] = entry
        return lookup

    def _get_string_lookup(self):
        """
        Return cached string address lookups.
        :return:
        """
        if hasattr(self, "_string_lookup") and self._string_lookup is not None:
            return self._string_lookup
        self._string_lookup = self._build_string_lookup()
        return self._string_lookup

    def find_strings(self, min_length=4, include_ascii=True, include_wide=True):
        """
        Recover printable strings from the full input image.
        :param min_length:
        :param include_ascii:
        :param include_wide:
        :return:
        """
        if self._strings_cache is None:
            data = self._get_binary_data()
            strings_found = []
            strings_found.extend(self._scan_ascii_strings(data, min_length=4))
            strings_found.extend(self._scan_wide_strings(data, min_length=4))
            unique = {}
            for entry in strings_found:
                key = (entry["file_offset"], entry["encoding"], entry["string"])
                unique[key] = entry
            self._strings_cache = sorted(unique.values(), key=lambda item: (item["file_offset"], item["encoding"]))
            self._string_lookup = None
        strings_found = []
        for entry in self._strings_cache:
            if entry["length"] < min_length:
                continue
            if entry["encoding"] == "ascii" and not include_ascii:
                continue
            if entry["encoding"] == "utf16le" and not include_wide:
                continue
            strings_found.append(dict(entry))
        return strings_found

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
        returns operand immediate as signed int when available
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

    def _decode_insn(self, ea):
        """
        Decode a single instruction at the provided offset.
        :param ea: instruction offset
        :return: capstone instruction or None
        """
        if ea is None or ea == self.BADADDR or ea < 0:
            return None
        code = self.data[ea:ea + self.MAX_BYTE_SIZE]
        for insn in self.md.disasm(code, ea, 1):
            return insn
        return None

    def _is_direct_target(self, value):
        """
        Return True when a branch/call target is a direct in-range offset.
        :param value:
        :return:
        """
        return isinstance(value, int) and 0 <= value < len(self.data)

    def _get_fallthrough(self, insn):
        """
        Return the next sequential instruction offset.
        :param insn:
        :return:
        """
        if not insn:
            return None
        next_ea = insn.address + insn.size
        if 0 <= next_ea < len(self.data):
            return next_ea
        return None

    def _operand_to_dict(self, insn, op):
        """
        Convert a capstone operand into a structured dictionary.
        :param insn:
        :param op:
        :return:
        """
        if op.type == X86_OP_REG:
            return {
                "type": "reg",
                "reg": insn.reg_name(op.reg),
                "size": op.size,
            }
        if op.type == X86_OP_IMM:
            return {
                "type": "imm",
                "value": op.imm,
                "size": op.size,
            }
        if op.type == X86_OP_MEM:
            address = None
            base = insn.reg_name(op.mem.base) if op.mem.base else None
            index = insn.reg_name(op.mem.index) if op.mem.index else None
            if op.mem.base == 0 and op.mem.index == 0 and op.mem.disp != 0:
                address = op.mem.disp
            elif base == "rip" and op.mem.index == 0:
                address = insn.address + insn.size + op.mem.disp
            return {
                "type": "mem",
                "segment": insn.reg_name(op.mem.segment) if op.mem.segment else None,
                "base": base,
                "index": index,
                "scale": op.mem.scale,
                "disp": op.mem.disp,
                "address": address,
                "symbol": self._lookup_import_label(address),
                "size": op.size,
            }
        return {
            "type": "unknown",
            "size": getattr(op, "size", None),
        }

    def _resolve_import_label_for_analysis_offset(self, ea, depth=1, visited=None):
        """
        Resolve an imported symbol name for a call/jump or thunk target.
        :param ea:
        :param depth:
        :param visited:
        :return:
        """
        if visited is None:
            visited = set()
        if depth < 0 or not self._is_direct_target(ea) or ea in visited:
            return None
        visited.add(ea)
        insn = self._decode_insn(ea)
        if not insn:
            return None
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                operand = self._operand_to_dict(insn, op)
                if operand.get("symbol"):
                    return operand["symbol"]
        if insn.mnemonic in CALL or insn.mnemonic in BNC:
            for op in insn.operands:
                if op.type == X86_OP_IMM and self._is_direct_target(op.imm):
                    return self._resolve_import_label_for_analysis_offset(op.imm, depth=depth - 1, visited=visited)
        return None

    def _get_function_label(self, ea):
        """
        Return an auto label for a recovered function start.
        :param ea:
        :return:
        """
        entry = self.get_entry_point()
        if entry and entry["analysis_offset"] == ea:
            return "entry_point"
        anchor = self.analysis_offset_to_va(ea)
        if anchor is None:
            anchor = ea
        return "sub_%x" % anchor

    def _get_code_label(self, ea):
        """
        Return an auto label for a code location.
        :param ea:
        :return:
        """
        function = self.get_function(ea)
        if function and function["start_ea"] == ea:
            return self._get_function_label(ea)
        anchor = self.analysis_offset_to_va(ea)
        if anchor is None:
            anchor = ea
        return "loc_%x" % anchor

    def _get_auto_data_label(self, address_info):
        """
        Return an auto label for a data location.
        :param address_info:
        :return:
        """
        anchor = address_info["va"]
        if anchor is None:
            anchor = address_info["file_offset"]
        prefix = "data"
        if address_info.get("section"):
            section_name = self._sanitize_label_component(address_info["section"], max_length=12).lower()
            if section_name:
                prefix = section_name
        return "%s_%x" % (prefix, anchor)

    def _get_candidate_address_kinds(self, value, preferred_kind=None):
        """
        Return candidate address domains for a numeric operand value.
        :param value:
        :param preferred_kind:
        :return:
        """
        candidates = []
        if preferred_kind in ("analysis", "rva", "va", "file"):
            candidates.append(preferred_kind)
        if self.pe:
            if value >= self.image_base:
                candidates.append("va")
            if self._is_analysis_offset(value):
                candidates.append("analysis")
            if self.rva_to_file_offset(value) is not None:
                candidates.append("rva")
            if 0 <= value < self._get_binary_length():
                candidates.append("file")
        else:
            if self._is_analysis_offset(value):
                candidates.extend(["analysis", "file"])
        ordered = []
        for candidate in candidates:
            if candidate not in ordered:
                ordered.append(candidate)
        return ordered

    def _get_reference_info(self, value, preferred_kind=None, allow_code=True):
        """
        Resolve a numeric operand into an annotated code/data reference.
        :param value:
        :param preferred_kind:
        :param allow_code:
        :return:
        """
        if not isinstance(value, int):
            return None
        cache_key = (preferred_kind, allow_code, value)
        if cache_key in self._label_cache:
            return self._label_cache[cache_key]
        for kind in self._get_candidate_address_kinds(value, preferred_kind=preferred_kind):
            address_info = self.get_binary_address_info(value, kind=kind)
            if not address_info:
                continue
            user_label = self.get_label(value, kind=kind)
            if user_label:
                result = {
                    "kind": "user",
                    "label": user_label,
                    "address_info": address_info,
                    "display": user_label,
                }
                self._label_cache[cache_key] = result
                return result
            import_name = self._lookup_import_label(address_info["va"])
            if import_name:
                result = {
                    "kind": "import",
                    "label": import_name,
                    "address_info": address_info,
                    "display": import_name,
                }
                self._label_cache[cache_key] = result
                return result
            lookup_key = kind if kind != "file" else "file"
            string_entry = self._get_string_lookup().get(lookup_key, {}).get(value)
            if string_entry:
                result = {
                    "kind": "string",
                    "label": string_entry["label"],
                    "address_info": address_info,
                    "string": string_entry["string"],
                    "encoding": string_entry["encoding"],
                    "display": string_entry["label"],
                }
                self._label_cache[cache_key] = result
                return result
            analysis_offset = address_info["analysis_offset"]
            if allow_code and analysis_offset is not None and not self._building_functions:
                function = self.get_function(analysis_offset)
                if function and function["start_ea"] == analysis_offset:
                    result = {
                        "kind": "function",
                        "label": self._get_function_label(analysis_offset),
                        "address_info": address_info,
                        "display": self._get_function_label(analysis_offset),
                    }
                    self._label_cache[cache_key] = result
                    return result
                if analysis_offset in self._get_recovered_instruction_starts():
                    result = {
                        "kind": "code",
                        "label": self._get_code_label(analysis_offset),
                        "address_info": address_info,
                        "display": self._get_code_label(analysis_offset),
                    }
                    self._label_cache[cache_key] = result
                    return result
            if address_info.get("section") and address_info["section"] != self.code_section_name:
                result = {
                    "kind": "data",
                    "label": self._get_auto_data_label(address_info),
                    "address_info": address_info,
                    "display": self._get_auto_data_label(address_info),
                }
                self._label_cache[cache_key] = result
                return result
        self._label_cache[cache_key] = None
        return None

    def get_label_for_address(self, value, kind="auto"):
        """
        Return the best known label for an address-like value.
        :param value:
        :param kind:
        :return:
        """
        reference = self._get_reference_info(value, preferred_kind=None if kind == "auto" else kind)
        if reference:
            return reference["label"]
        return None

    def _get_operand_reference_info(self, mnemonic, operand):
        """
        Resolve an operand into a labeled address reference when possible.
        :param mnemonic:
        :param operand:
        :return:
        """
        if operand["type"] == "imm":
            allow_code = mnemonic in CALL or mnemonic in BNC or mnemonic in COND_BRANCH
            return self._get_reference_info(operand["value"], allow_code=allow_code)
        if operand["type"] != "mem" or operand.get("address") is None:
            return None
        preferred_kind = None
        if operand.get("base") == "rip":
            preferred_kind = "analysis"
        elif self.pe and operand.get("base") is None and operand.get("index") is None:
            preferred_kind = "va"
        elif self._is_analysis_offset(operand["address"]):
            preferred_kind = "analysis"
        return self._get_reference_info(operand["address"], preferred_kind=preferred_kind, allow_code=False)

    def _get_operand_replacement_candidates(self, operand):
        """
        Return textual literals that may appear in capstone's operand string.
        :param operand:
        :return:
        """
        candidates = []
        if operand["type"] == "imm":
            values = [operand.get("value")]
        elif operand["type"] == "mem":
            values = [operand.get("address"), operand.get("disp")]
        else:
            values = []
        for value in values:
            if not isinstance(value, int):
                continue
            candidates.extend([
                "0x%x" % value,
                "0x%X" % value,
                str(value),
                "-0x%x" % abs(value),
            ])
        ordered = []
        for candidate in candidates:
            if candidate and candidate not in ordered:
                ordered.append(candidate)
        return ordered

    def _render_labeled_op_str(self, instruction):
        """
        Apply operand labels to an instruction operand string.
        :param instruction:
        :return:
        """
        display_op_str = instruction["op_str"]
        appended_labels = []
        for operand in instruction["operands"]:
            label = operand.get("label")
            if not label:
                continue
            replaced = False
            for candidate in self._get_operand_replacement_candidates(operand):
                if candidate in display_op_str:
                    display_op_str = display_op_str.replace(candidate, label, 1)
                    replaced = True
                    break
            if not replaced and label not in appended_labels:
                appended_labels.append(label)
        return display_op_str, appended_labels

    def _get_stack_register_names(self):
        """
        Return frame and stack register names for the active bitness.
        :return:
        """
        if self.bit == 64:
            return {
                "frame": "rbp",
                "stack": "rsp",
            }
        return {
            "frame": "ebp",
            "stack": "esp",
        }

    def _format_stack_label(self, base_reg, disp):
        """
        Build an IDA-like label for a stack slot.
        :param base_reg:
        :param disp:
        :return:
        """
        registers = self._get_stack_register_names()
        if base_reg == registers["frame"]:
            if disp < 0:
                return "var_%x" % abs(disp)
            if disp > 0:
                return "arg_%x" % disp
            return "__saved_%s" % base_reg
        if base_reg == registers["stack"]:
            if disp < 0:
                return "stack_%x" % abs(disp)
            if disp > 0:
                return "stack_plus_%x" % disp
            return "__saved_%s" % base_reg
        return None

    def _build_stack_reference(self, instruction_address, operand_index, operand):
        """
        Convert a stack-based memory operand into a structured stack reference.
        :param instruction_address:
        :param operand_index:
        :param operand:
        :return:
        """
        if operand["type"] != "mem":
            return None
        registers = self._get_stack_register_names()
        if operand.get("base") not in (registers["frame"], registers["stack"]):
            return None
        disp = operand.get("disp", 0)
        kind = "stack"
        if operand["base"] == registers["frame"]:
            if disp < 0:
                kind = "local"
            elif disp > 0:
                kind = "argument"
            else:
                kind = "saved_frame"
        elif operand["base"] == registers["stack"] and disp == 0:
            kind = "stack_top"
        return {
            "from": instruction_address,
            "operand_index": operand_index,
            "base": operand["base"],
            "disp": disp,
            "size": operand.get("size"),
            "kind": kind,
            "label": self._format_stack_label(operand["base"], disp),
        }

    def _collect_instruction_stack_refs(self, instruction):
        """
        Return stack references originating from one instruction.
        :param instruction:
        :return:
        """
        refs = []
        for index, operand in enumerate(instruction["operands"]):
            stack_ref = self._build_stack_reference(instruction["address"], index, operand)
            if stack_ref:
                refs.append(stack_ref)
                operand["stack_ref"] = stack_ref
                if stack_ref["label"] and stack_ref["label"] not in instruction["labels"]:
                    instruction["labels"].append(stack_ref["label"])
        instruction["labels"] = sorted(set(instruction["labels"]))
        return refs

    def _detect_frame_pointer_usage(self, instructions):
        """
        Heuristically detect frame-pointer usage for a function.
        :param instructions:
        :return:
        """
        registers = self._get_stack_register_names()
        frame_reg = registers["frame"]
        stack_reg = registers["stack"]
        if len(instructions) >= 2:
            first = instructions[0]
            second = instructions[1]
            if (
                first["mnemonic"] == "push"
                and first["operands"]
                and first["operands"][0].get("type") == "reg"
                and first["operands"][0].get("reg") == frame_reg
                and second["mnemonic"] == "mov"
                and len(second["operands"]) >= 2
                and second["operands"][0].get("type") == "reg"
                and second["operands"][1].get("type") == "reg"
                and second["operands"][0].get("reg") == frame_reg
                and second["operands"][1].get("reg") == stack_reg
            ):
                return True
        return any(
            operand.get("type") == "mem" and operand.get("base") == frame_reg
            for instruction in instructions
            for operand in instruction["operands"]
        )

    def _estimate_stack_allocation(self, instructions):
        """
        Estimate stack allocation size from the early function prologue.
        :param instructions:
        :return:
        """
        registers = self._get_stack_register_names()
        stack_reg = registers["stack"]
        max_prologue = min(len(instructions), 8)
        for instruction in instructions[:max_prologue]:
            if (
                instruction["mnemonic"] == "sub"
                and len(instruction["operands"]) >= 2
                and instruction["operands"][0].get("type") == "reg"
                and instruction["operands"][0].get("reg") == stack_reg
                and instruction["operands"][1].get("type") == "imm"
                and isinstance(instruction["operands"][1].get("value"), int)
                and instruction["operands"][1]["value"] > 0
            ):
                return instruction["operands"][1]["value"]
        return 0

    def _collect_saved_registers(self, instructions):
        """
        Recover likely callee-saved register saves from the prologue.
        :param instructions:
        :return:
        """
        registers = self._get_stack_register_names()
        saved = []
        max_prologue = min(len(instructions), 8)
        for instruction in instructions[:max_prologue]:
            if instruction["mnemonic"] != "push" or not instruction["operands"]:
                continue
            operand = instruction["operands"][0]
            if operand.get("type") != "reg":
                continue
            reg_name = operand.get("reg")
            if reg_name not in (registers["frame"], registers["stack"]) and reg_name not in saved:
                saved.append(reg_name)
        return saved

    def _summarize_function_stack(self, function):
        """
        Build a function-level stack summary.
        :param function:
        :return:
        """
        instructions = function["instructions"]
        frame_pointer = self._detect_frame_pointer_usage(instructions)
        registers = self._get_stack_register_names()
        refs = []
        slots = {}
        for instruction in instructions:
            for ref in instruction.get("stack_refs", []):
                refs.append(ref)
                key = (ref["base"], ref["disp"])
                slot = slots.setdefault(key, {
                    "base": ref["base"],
                    "disp": ref["disp"],
                    "label": ref["label"],
                    "kind": ref["kind"],
                    "size": ref["size"],
                    "references": [],
                })
                slot["references"].append(ref["from"])
                if slot["size"] is None and ref.get("size") is not None:
                    slot["size"] = ref["size"]
        locals_list = []
        arguments = []
        for slot in sorted(slots.values(), key=lambda item: (item["base"], item["disp"])):
            slot["references"] = sorted(set(slot["references"]))
            if slot["kind"] == "local":
                locals_list.append(slot)
            elif slot["kind"] == "argument":
                arguments.append(slot)
        stack_summary = {
            "uses_frame_pointer": frame_pointer,
            "frame_pointer": registers["frame"] if frame_pointer else None,
            "stack_pointer": registers["stack"],
            "stack_allocation": self._estimate_stack_allocation(instructions),
            "saved_registers": self._collect_saved_registers(instructions),
            "locals": locals_list,
            "arguments": arguments,
            "stack_slots": sorted(slots.values(), key=lambda item: (item["base"], item["disp"])),
            "references": refs,
        }
        return stack_summary

    def _canonicalize_register_name(self, reg_name):
        """
        Collapse subregister names into a stable general-purpose register family.
        :param reg_name:
        :return:
        """
        if not reg_name:
            return None
        register_groups = {
            "rax": {"rax", "eax", "ax", "al", "ah"},
            "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
            "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
            "rdx": {"rdx", "edx", "dx", "dl", "dh"},
            "rsi": {"rsi", "esi", "si", "sil"},
            "rdi": {"rdi", "edi", "di", "dil"},
            "rbp": {"rbp", "ebp", "bp", "bpl"},
            "rsp": {"rsp", "esp", "sp", "spl"},
            "r8": {"r8", "r8d", "r8w", "r8b"},
            "r9": {"r9", "r9d", "r9w", "r9b"},
            "r10": {"r10", "r10d", "r10w", "r10b"},
            "r11": {"r11", "r11d", "r11w", "r11b"},
            "r12": {"r12", "r12d", "r12w", "r12b"},
            "r13": {"r13", "r13d", "r13w", "r13b"},
            "r14": {"r14", "r14d", "r14w", "r14b"},
            "r15": {"r15", "r15d", "r15w", "r15b"},
        }
        lowered = reg_name.lower()
        for canonical, variants in register_groups.items():
            if lowered in variants:
                return canonical
        return lowered

    def _evaluate_constant_operand(self, instruction, operand, state):
        """
        Evaluate an operand into a constant when possible.
        :param instruction:
        :param operand:
        :param state:
        :return:
        """
        if operand["type"] == "imm":
            return operand["value"]
        if operand["type"] == "reg":
            return state.get(self._canonicalize_register_name(operand["reg"]))
        if operand["type"] == "mem":
            if operand.get("base") == "rip" and operand.get("address") is not None:
                return operand["address"]
            if operand.get("base") is None and operand.get("index") is None and operand.get("address") is not None:
                return operand["address"]
        return None

    def _apply_constant_write(self, state, reg_name, value):
        """
        Apply a constant register write to state.
        :param state:
        :param reg_name:
        :param value:
        :return:
        """
        canonical = self._canonicalize_register_name(reg_name)
        if canonical is None:
            return state
        if value is None:
            state.pop(canonical, None)
        else:
            state[canonical] = value
        return state

    def _transfer_instruction_constants(self, instruction, state):
        """
        Propagate constant register state across one instruction.
        :param instruction:
        :param state:
        :return:
        """
        new_state = dict(state)
        operands = instruction["operands"]
        constants_used = {}
        for index, operand in enumerate(operands):
            value = self._evaluate_constant_operand(instruction, operand, new_state)
            if value is not None:
                constants_used[index] = value
        if not operands:
            return new_state, constants_used
        dst = operands[0]
        dst_reg = dst["reg"] if dst.get("type") == "reg" else None
        mnemonic = instruction["mnemonic"]
        if dst_reg:
            if mnemonic in ("mov", "movabs") and len(operands) >= 2:
                self._apply_constant_write(new_state, dst_reg, self._evaluate_constant_operand(instruction, operands[1], new_state))
            elif mnemonic == "lea" and len(operands) >= 2 and operands[1]["type"] == "mem":
                value = self._evaluate_constant_operand(instruction, operands[1], new_state)
                self._apply_constant_write(new_state, dst_reg, value)
            elif mnemonic == "xor" and len(operands) >= 2 and operands[1].get("type") == "reg" and self._canonicalize_register_name(dst_reg) == self._canonicalize_register_name(operands[1]["reg"]):
                self._apply_constant_write(new_state, dst_reg, 0)
            elif mnemonic in ("add", "sub", "and", "or", "shl", "shr", "sar", "imul") and len(operands) >= 2:
                lhs = self._evaluate_constant_operand(instruction, dst, new_state)
                rhs = self._evaluate_constant_operand(instruction, operands[1], new_state)
                value = None
                if lhs is not None and rhs is not None:
                    if mnemonic == "add":
                        value = lhs + rhs
                    elif mnemonic == "sub":
                        value = lhs - rhs
                    elif mnemonic == "and":
                        value = lhs & rhs
                    elif mnemonic == "or":
                        value = lhs | rhs
                    elif mnemonic == "shl":
                        value = lhs << rhs
                    elif mnemonic in ("shr", "sar"):
                        value = lhs >> rhs
                    elif mnemonic == "imul":
                        value = lhs * rhs
                self._apply_constant_write(new_state, dst_reg, value)
            elif mnemonic in ("inc", "dec"):
                lhs = self._evaluate_constant_operand(instruction, dst, new_state)
                if lhs is None:
                    self._apply_constant_write(new_state, dst_reg, None)
                else:
                    self._apply_constant_write(new_state, dst_reg, lhs + (1 if mnemonic == "inc" else -1))
            elif mnemonic in ("pop",):
                self._apply_constant_write(new_state, dst_reg, None)
            elif mnemonic not in ("cmp", "test", "push", "call"):
                self._apply_constant_write(new_state, dst_reg, None)
        for reg in instruction.get("regs_write", []):
            canonical = self._canonicalize_register_name(reg)
            if canonical and dst_reg and canonical == self._canonicalize_register_name(dst_reg):
                continue
            if canonical and reg.lower() in ("eflags", "rflags"):
                continue
            if canonical and canonical.startswith("xmm"):
                continue
        return new_state, constants_used

    def _resolve_pointer_value(self, raw_value):
        """
        Normalize a raw pointer-sized table entry into an analysis offset when possible.
        :param raw_value:
        :return:
        """
        if not isinstance(raw_value, int):
            return None
        candidate_kinds = []
        if self.pe:
            candidate_kinds.extend(["va", "rva"])
        candidate_kinds.extend(["analysis", "file"])
        for kind in candidate_kinds:
            info = self.get_binary_address_info(raw_value, kind=kind)
            if info and info["analysis_offset"] is not None and self._decode_insn(info["analysis_offset"]):
                return info["analysis_offset"]
        return None

    def _read_integer_at_file_offset(self, file_offset, size):
        """
        Read a little-endian integer from the full input image.
        :param file_offset:
        :param size:
        :return:
        """
        if size not in (4, 8):
            return None
        data = self._get_binary_data()
        chunk = data[file_offset:file_offset + size]
        if len(chunk) != size:
            return None
        return int.from_bytes(chunk, "little", signed=False)

    def _resolve_indirect_branch_targets(self, instruction, max_entries=32):
        """
        Resolve likely jump-table targets for an indirect branch.
        :param instruction:
        :param max_entries:
        :return:
        """
        if instruction["target"] is not None or instruction["mnemonic"] not in BNC:
            return []
        if not instruction["operands"]:
            return []
        operand = instruction["operands"][0]
        if operand.get("type") != "mem":
            return []
        if operand.get("index") is None and operand.get("base") not in (None, "rip"):
            return []
        table_address = operand.get("address")
        if table_address is None and operand.get("base") is None and operand.get("disp"):
            table_address = operand.get("disp")
        if table_address is None:
            return []
        preferred_kind = "analysis" if operand.get("base") == "rip" else ("va" if self.pe else "analysis")
        table_info = self.get_binary_address_info(table_address, kind=preferred_kind)
        if not table_info:
            return []
        entry_size = operand.get("scale") if operand.get("scale") in (4, 8) else (8 if self.bit == 64 else 4)
        targets = []
        for index in range(max_entries):
            raw_value = self._read_integer_at_file_offset(table_info["file_offset"] + (index * entry_size), entry_size)
            target = self._resolve_pointer_value(raw_value)
            if target is None:
                break
            targets.append(target)
        unique_targets = []
        for target in targets:
            if target not in unique_targets:
                unique_targets.append(target)
        if len(unique_targets) < 2:
            return []
        return unique_targets

    def _normalize_symbol_leaf_name(self, symbol_name):
        """
        Return the rightmost symbol component for import/name matching.
        :param symbol_name:
        :return:
        """
        if not symbol_name:
            return None
        leaf = symbol_name.split("!")[-1]
        return leaf.strip()

    def _is_noreturn_symbol(self, symbol_name):
        """
        Return True when a symbol name is known noreturn.
        :param symbol_name:
        :return:
        """
        leaf = self._normalize_symbol_leaf_name(symbol_name)
        if not leaf:
            return False
        return leaf in KNOWN_NORETURN_IMPORTS

    def _is_noreturn_call_instruction(self, instruction):
        """
        Return True when a call instruction is likely noreturn.
        :param instruction:
        :return:
        """
        if not instruction or not instruction.get("is_call"):
            return False
        if self._is_noreturn_symbol(instruction.get("import_name")):
            return True
        target = instruction.get("target")
        if self._is_direct_target(target) and not self._building_functions:
            function = self.get_function(target)
            if function:
                classification = function.get("classification") or self._classify_function(function)
                if classification and "noreturn" in classification.get("flags", []):
                    return True
        return False

    def _merge_constant_states(self, states):
        """
        Intersect predecessor constant states.
        :param states:
        :return:
        """
        states = [state for state in states if state is not None]
        if not states:
            return {}
        merged = dict(states[0])
        for key in list(merged.keys()):
            for state in states[1:]:
                if key not in state or state[key] != merged[key]:
                    merged.pop(key, None)
                    break
        return merged

    def _analyze_function_data_flow(self, function):
        """
        Perform lightweight constant propagation over a recovered function CFG.
        :param function:
        :return:
        """
        blocks = function.get("basic_blocks", [])
        if not blocks:
            return {
                "block_states": {},
                "instruction_states": {},
            }
        block_by_start = {block["start"]: block for block in blocks}
        in_states = {block["start"]: None for block in blocks}
        out_states = {block["start"]: None for block in blocks}
        entry_start = blocks[0]["start"]
        in_states[entry_start] = {}
        changed = True
        instruction_states = {}
        while changed:
            changed = False
            for block in blocks:
                start = block["start"]
                if start != entry_start:
                    pred_states = [out_states.get(pred) for pred in block["preds"]]
                    merged = self._merge_constant_states(pred_states)
                    if in_states[start] != merged:
                        in_states[start] = merged
                        changed = True
                state = dict(in_states[start] or {})
                for instruction in block["instructions"]:
                    instruction_states.setdefault(instruction["address"], {})
                    instruction_states[instruction["address"]]["in_constants"] = dict(state)
                    state, constants_used = self._transfer_instruction_constants(instruction, state)
                    instruction_states[instruction["address"]]["out_constants"] = dict(state)
                    instruction_states[instruction["address"]]["constant_operands"] = constants_used
                if out_states[start] != state:
                    out_states[start] = state
                    changed = True
        instruction_map = {instruction["address"]: instruction for instruction in function["instructions"]}
        for address, state in instruction_states.items():
            instruction = instruction_map.get(address)
            if not instruction:
                continue
            instruction["in_constants"] = dict(state.get("in_constants", {}))
            instruction["out_constants"] = dict(state.get("out_constants", {}))
            instruction["constant_operands"] = dict(state.get("constant_operands", {}))
        return {
            "block_states": {
                block["start"]: {
                    "in_constants": dict(in_states[block["start"]] or {}),
                    "out_constants": dict(out_states[block["start"]] or {}),
                }
                for block in blocks
            },
            "instruction_states": instruction_states,
        }

    def get_instruction(self, ea):
        """
        Return a structured instruction object for a single offset.
        :param ea: instruction offset
        :return: dict or None
        """
        insn = self._decode_insn(ea)
        if not insn:
            return None
        address_info = self.get_address_info(ea)
        regs_read, regs_write = insn.regs_access()
        target = self.get_operand_value(ea, 0)
        is_call = insn.mnemonic in CALL
        is_jump = insn.mnemonic in BNC or insn.mnemonic in COND_BRANCH
        is_return = insn.mnemonic in END
        fallthrough = None if insn.mnemonic in BNC or is_return else self._get_fallthrough(insn)
        operands = [self._operand_to_dict(insn, op) for op in insn.operands]
        data_refs = []
        labels = []
        for index, operand in enumerate(operands):
            reference = self._get_operand_reference_info(insn.mnemonic, operand)
            if reference:
                operand["label"] = reference["label"]
                operand["ref_kind"] = reference["kind"]
                operand["ref_address"] = reference["address_info"]
                if reference["kind"] in ("import", "string", "data"):
                    data_refs.append({
                        "from": insn.address,
                        "to": reference["address_info"]["analysis_offset"],
                        "to_rva": reference["address_info"]["rva"],
                        "to_va": reference["address_info"]["va"],
                        "to_file_offset": reference["address_info"]["file_offset"],
                        "type": reference["kind"],
                        "label": reference["label"],
                        "operand_index": index,
                    })
                labels.append(reference["label"])
        import_name = None
        for operand in operands:
            if operand.get("symbol"):
                import_name = operand["symbol"]
                break
            if operand.get("ref_kind") == "import":
                import_name = operand["label"]
                break
        if import_name is None and is_call and self._is_direct_target(target):
            import_name = self._resolve_import_label_for_analysis_offset(target, depth=1)
        comment = self.get_comment(insn.address, repeatable=False)
        repeatable_comment = self.get_comment(insn.address, repeatable=True)
        instruction = {
            "address": insn.address,
            "size": insn.size,
            "bytes": bytes(insn.bytes),
            "bytes_hex": bytes(insn.bytes).hex(),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "operands": operands,
            "groups": [insn.group_name(group_id) for group_id in insn.groups],
            "regs_read": [insn.reg_name(reg_id) for reg_id in regs_read],
            "regs_write": [insn.reg_name(reg_id) for reg_id in regs_write],
            "is_call": is_call,
            "is_jump": is_jump,
            "is_return": is_return,
            "target": target if self._is_direct_target(target) else None,
            "fallthrough": fallthrough,
            "rva": address_info["rva"],
            "va": address_info["va"],
            "file_offset": address_info["file_offset"],
            "import_name": import_name,
            "labels": sorted(set(labels)),
            "data_refs": data_refs,
            "comment": comment,
            "repeatable_comment": repeatable_comment,
        }
        instruction["stack_refs"] = self._collect_instruction_stack_refs(instruction)
        instruction["resolved_targets"] = self._resolve_indirect_branch_targets(instruction)
        instruction["is_noreturn"] = self._is_noreturn_call_instruction(instruction)
        if instruction["is_noreturn"]:
            instruction["fallthrough"] = None
        display_op_str, inline_labels = self._render_labeled_op_str(instruction)
        instruction["display_op_str"] = display_op_str
        instruction["display_text"] = ("%s %s" % (instruction["mnemonic"], display_op_str)).rstrip()
        instruction["inline_labels"] = inline_labels
        instruction["text"] = self._format_instruction_text(instruction)
        return instruction

    def _format_instruction_text(self, instruction):
        """
        Format a disassembly line with any available annotation.
        :param instruction:
        :return:
        """
        display_op_str = instruction.get("display_op_str")
        appended_labels = instruction.get("inline_labels")
        if display_op_str is None or appended_labels is None:
            display_op_str, appended_labels = self._render_labeled_op_str(instruction)
        text = ("%s %s" % (instruction["mnemonic"], display_op_str)).rstrip()
        annotations = []
        if instruction.get("import_name") and instruction["import_name"] not in text:
            annotations.append(instruction["import_name"])
        for label in appended_labels:
            if label not in annotations:
                annotations.append(label)
        for ref in instruction.get("data_refs", []):
            if ref["type"] == "string" and ref["label"] not in annotations and ref["label"] not in text:
                annotations.append(ref["label"])
        if instruction.get("comment"):
            annotations.append(instruction["comment"])
        repeatable_comment = instruction.get("repeatable_comment")
        if repeatable_comment and repeatable_comment != instruction.get("comment"):
            annotations.append("repeatable:%s" % repeatable_comment)
        if annotations:
            return "%s ; %s" % (text, ", ".join(annotations))
        return text

    def get_instructions(self, start=0, end=None, max_instructions=MAX_INSTRU):
        """
        Return structured instructions in a linear disassembly range.
        :param start: start offset
        :param end: end offset
        :param max_instructions: limit decoded instructions
        :return: list of instruction dicts
        """
        if end is None or end > len(self.data):
            end = len(self.data)
        instructions = []
        curr_addr = start
        while curr_addr is not None and curr_addr != self.BADADDR and curr_addr < end:
            if len(instructions) >= max_instructions:
                break
            insn = self.get_instruction(curr_addr)
            if not insn:
                break
            instructions.append(insn)
            next_ea = insn["address"] + insn["size"]
            if next_ea <= curr_addr:
                break
            curr_addr = next_ea
        return instructions

    def _find_prologue_candidates(self, start=0, end=None):
        """
        Find likely function prologue offsets for x86/x64 code.
        :param start:
        :param end:
        :return:
        """
        if end is None or end > len(self.data):
            end = len(self.data)
        patterns = [b"\x55\x89\xe5", b"\x55\x8b\xec"]
        if self.bit == 64:
            patterns.insert(0, b"\x55\x48\x89\xe5")
        candidates = set()
        for pattern in patterns:
            offset = start
            while offset < end:
                found = self.data.find(pattern, offset, end)
                if found == -1:
                    break
                candidates.add(found)
                offset = found + 1
        return sorted(candidates)

    def _collect_function_candidate_starts(self, start=0, end=None):
        """
        Gather likely function entry points from prologues and direct calls.
        :param start:
        :param end:
        :return:
        """
        if end is None or end > len(self.data):
            end = len(self.data)
        candidates = set(self._find_prologue_candidates(start, end))
        if start == 0 and self._decode_insn(0):
            candidates.add(0)
        for insn in self.get_instructions(start, end):
            if insn["is_call"] and self._is_direct_target(insn["target"]):
                candidates.add(insn["target"])
        return sorted(candidates)

    def _walk_function(self, start_ea, end=None):
        """
        Follow control flow for a function without descending into callees.
        :param start_ea:
        :param end:
        :return:
        """
        if end is None or end > len(self.data):
            end = len(self.data)
        if not self._is_direct_target(start_ea):
            return None
        worklist = [start_ea]
        visited = set()
        instructions = {}
        while worklist:
            curr_addr = worklist.pop()
            if curr_addr in visited or curr_addr >= end:
                continue
            insn = self.get_instruction(curr_addr)
            if not insn:
                continue
            visited.add(curr_addr)
            instructions[curr_addr] = insn
            if insn["is_return"]:
                continue
            if insn["is_call"]:
                if insn["is_noreturn"]:
                    continue
                if insn["fallthrough"] is not None:
                    worklist.append(insn["fallthrough"])
                continue
            if insn["mnemonic"] in BNC:
                if self._is_direct_target(insn["target"]):
                    worklist.append(insn["target"])
                elif insn.get("resolved_targets"):
                    worklist.extend(insn["resolved_targets"])
                continue
            if insn["mnemonic"] in COND_BRANCH:
                if self._is_direct_target(insn["target"]):
                    worklist.append(insn["target"])
                if insn["fallthrough"] is not None:
                    worklist.append(insn["fallthrough"])
                continue
            if insn["fallthrough"] is not None:
                worklist.append(insn["fallthrough"])
        if not instructions:
            return None
        ordered = [instructions[key] for key in sorted(instructions)]
        end_ea = max(insn["address"] + insn["size"] for insn in ordered)
        basic_blocks = self._build_basic_blocks_from_instructions(ordered)
        call_targets = sorted({
            insn["target"] for insn in ordered
            if insn["is_call"] and self._is_direct_target(insn["target"])
        })
        return {
            "start_ea": start_ea,
            "end_ea": end_ea,
            "size": end_ea - start_ea,
            "instruction_count": len(ordered),
            "instructions": ordered,
            "basic_blocks": basic_blocks,
            "calls_from": call_targets,
            "start_rva": self.analysis_offset_to_rva(start_ea),
            "end_rva": self.analysis_offset_to_rva(end_ea),
            "start_va": self.analysis_offset_to_va(start_ea),
            "end_va": self.analysis_offset_to_va(end_ea),
            "stack_analysis": None,
            "data_flow": None,
        }

    def _get_function_thunk_target(self, function):
        """
        Return a likely thunk target when a recovered function is a simple wrapper.
        :param function:
        :return:
        """
        if not function or function["instruction_count"] > 3:
            return None
        terminal = function["instructions"][-1]
        if terminal["mnemonic"] in BNC and terminal.get("target") is not None:
            return terminal["target"]
        if terminal["mnemonic"] in CALL and terminal.get("target") is not None:
            return terminal.get("target")
        return None

    def _classify_function(self, function):
        """
        Classify a recovered function using lightweight x86/x64 heuristics.
        :param function:
        :return:
        """
        if not function:
            return None
        entry = self.get_entry_point()
        thunk_target = self._get_function_thunk_target(function)
        terminal = function["instructions"][-1]
        flags = []
        func_type = "function"
        if entry and function["start_ea"] == entry["analysis_offset"]:
            flags.append("entrypoint")
            func_type = "entrypoint"
        if not function.get("calls_from"):
            flags.append("leaf")
        if terminal["mnemonic"] in BNC and terminal.get("target") is not None:
            flags.append("tail_call")
        if any(instruction.get("is_noreturn") for instruction in function["instructions"]):
            flags.append("noreturn")
        if thunk_target is not None:
            flags.append("thunk")
            func_type = "thunk"
            import_name = self._resolve_import_label_for_analysis_offset(thunk_target, depth=1)
            if import_name or terminal.get("import_name"):
                flags.append("import_thunk")
                func_type = "import_thunk"
                if self._is_noreturn_symbol(import_name or terminal.get("import_name")):
                    flags.append("noreturn")
                    func_type = "noreturn_import_thunk"
        classification = {
            "type": func_type,
            "flags": sorted(set(flags)),
            "thunk_target": thunk_target,
        }
        return classification

    def find_functions(self, start=0, end=None):
        """
        Recover likely functions from linear x86/x64 code.
        :param start:
        :param end:
        :return:
        """
        if end is None or end > len(self.data):
            end = len(self.data)
        cache_key = (start, end)
        if cache_key in self._functions_cache:
            return self._functions_cache[cache_key]
        functions = []
        covered = set()
        previous_state = self._building_functions
        self._building_functions = True
        try:
            for candidate in self._collect_function_candidate_starts(start, end):
                if candidate in covered:
                    continue
                function = self._walk_function(candidate, end=end)
                if not function:
                    continue
                function["label"] = self._get_function_label(function["start_ea"])
                function["classification"] = self._classify_function(function)
                function["stack_analysis"] = self._summarize_function_stack(function)
                function["data_flow"] = self._analyze_function_data_flow(function)
                functions.append(function)
                for insn in function["instructions"]:
                    covered.add(insn["address"])
        finally:
            self._building_functions = previous_state
        self._functions_cache[cache_key] = functions
        self._recovered_instruction_starts_cache = None
        self._recovered_prev_head_cache = None
        self._label_cache = {}
        return functions

    def get_function(self, ea):
        """
        Return the recovered function containing the provided offset.
        :param ea:
        :return:
        """
        for function in self.find_functions():
            if function["start_ea"] <= ea < function["end_ea"]:
                return function
        return None

    def get_function_classification(self, func):
        """
        Return classification metadata for a recovered function.
        :param func:
        :return:
        """
        function = self._normalize_function(func)
        if not function:
            return None
        if "classification" not in function:
            function["classification"] = self._classify_function(function)
        return function["classification"]

    def get_stack_references(self, func):
        """
        Return stack references for a recovered function.
        :param func:
        :return:
        """
        function = self._normalize_function(func)
        if not function:
            return []
        if function.get("stack_analysis") is None:
            function["stack_analysis"] = self._summarize_function_stack(function)
        return list(function["stack_analysis"]["references"])

    def get_stack_variables(self, func):
        """
        Return recovered locals/arguments for a function.
        :param func:
        :return:
        """
        function = self._normalize_function(func)
        if not function:
            return None
        if function.get("stack_analysis") is None:
            function["stack_analysis"] = self._summarize_function_stack(function)
        return {
            "locals": list(function["stack_analysis"]["locals"]),
            "arguments": list(function["stack_analysis"]["arguments"]),
            "saved_registers": list(function["stack_analysis"]["saved_registers"]),
            "stack_allocation": function["stack_analysis"]["stack_allocation"],
            "uses_frame_pointer": function["stack_analysis"]["uses_frame_pointer"],
        }

    def get_data_flow(self, func):
        """
        Return lightweight constant-propagation data for a function.
        :param func:
        :return:
        """
        function = self._normalize_function(func)
        if not function:
            return None
        if function.get("data_flow") is None:
            function["data_flow"] = self._analyze_function_data_flow(function)
        return function["data_flow"]

    def get_register_constants_at(self, func, ea, when="in"):
        """
        Return register constants before or after one instruction.
        :param func:
        :param ea:
        :param when:
        :return:
        """
        data_flow = self.get_data_flow(func)
        if not data_flow:
            return None
        instruction_state = data_flow["instruction_states"].get(ea)
        if not instruction_state:
            return None
        if when == "out":
            return dict(instruction_state.get("out_constants", {}))
        return dict(instruction_state.get("in_constants", {}))

    def _normalize_function(self, func):
        """
        Normalize a function input into a recovered function dictionary.
        :param func:
        :return:
        """
        if isinstance(func, dict):
            return func
        if isinstance(func, int):
            function = self.get_function(func)
            if function:
                return function
            return self._walk_function(func)
        return None

    def _collect_analysis_instructions(self, start=0, end=None):
        """
        Collect instructions from recovered functions, with linear fallback.
        :param start:
        :param end:
        :return:
        """
        instructions = {}
        for function in self.find_functions(start=start, end=end):
            for insn in function["instructions"]:
                instructions[insn["address"]] = insn
        if instructions:
            return [instructions[key] for key in sorted(instructions)]
        return self.get_instructions(start=start, end=end)

    def _instruction_xrefs(self, instruction, include_fallthrough=False):
        """
        Return code xrefs originating from one instruction.
        :param instruction:
        :param include_fallthrough:
        :return:
        """
        refs = []
        if instruction["is_call"] and self._is_direct_target(instruction["target"]):
            refs.append({
                "from": instruction["address"],
                "to": instruction["target"],
                "type": "call",
                "mnemonic": instruction["mnemonic"],
            })
        elif instruction["mnemonic"] in COND_BRANCH and self._is_direct_target(instruction["target"]):
            refs.append({
                "from": instruction["address"],
                "to": instruction["target"],
                "type": "branch",
                "mnemonic": instruction["mnemonic"],
            })
        elif instruction["mnemonic"] in BNC and self._is_direct_target(instruction["target"]):
            refs.append({
                "from": instruction["address"],
                "to": instruction["target"],
                "type": "jump",
                "mnemonic": instruction["mnemonic"],
            })
        elif instruction["mnemonic"] in BNC and instruction.get("resolved_targets"):
            for target in instruction["resolved_targets"]:
                refs.append({
                    "from": instruction["address"],
                    "to": target,
                    "type": "indirect_jump",
                    "mnemonic": instruction["mnemonic"],
                })
        if include_fallthrough and instruction["fallthrough"] is not None:
            refs.append({
                "from": instruction["address"],
                "to": instruction["fallthrough"],
                "type": "flow",
                "mnemonic": instruction["mnemonic"],
            })
        return refs

    def get_code_xrefs(self, start=0, end=None, include_fallthrough=False):
        """
        Return direct code xrefs recovered from the binary.
        :param start:
        :param end:
        :param include_fallthrough:
        :return:
        """
        refs = []
        for instruction in self._collect_analysis_instructions(start=start, end=end):
            refs.extend(self._instruction_xrefs(instruction, include_fallthrough=include_fallthrough))
        return refs

    def _instruction_data_xrefs(self, instruction):
        """
        Return labeled data-oriented references from one instruction.
        :param instruction:
        :return:
        """
        return list(instruction.get("data_refs", []))

    def get_data_xrefs(self, start=0, end=None):
        """
        Return data xrefs recovered from the binary.
        :param start:
        :param end:
        :return:
        """
        refs = []
        for instruction in self._collect_analysis_instructions(start=start, end=end):
            refs.extend(self._instruction_data_xrefs(instruction))
        return refs

    def get_data_xrefs_from(self, ea):
        """
        Return data references originating from a single instruction.
        :param ea:
        :return:
        """
        instruction = self.get_instruction(ea)
        if not instruction:
            return []
        return self._instruction_data_xrefs(instruction)

    def get_data_xrefs_to(self, value, kind="auto", start=0, end=None):
        """
        Return data references targeting an address-like value.
        :param value:
        :param kind:
        :param start:
        :param end:
        :return:
        """
        candidates = set()
        if kind == "auto":
            for candidate_kind in self._get_candidate_address_kinds(value):
                address_info = self.get_binary_address_info(value, kind=candidate_kind)
                if address_info:
                    for ref_value in ("analysis_offset", "rva", "va", "file_offset"):
                        if address_info[ref_value] is not None:
                            candidates.add((ref_value, address_info[ref_value]))
        else:
            address_info = self.get_binary_address_info(value, kind=kind)
            if not address_info:
                return []
            for ref_value in ("analysis_offset", "rva", "va", "file_offset"):
                if address_info[ref_value] is not None:
                    candidates.add((ref_value, address_info[ref_value]))
        refs = []
        for ref in self.get_data_xrefs(start=start, end=end):
            if (
                ("analysis_offset", ref.get("to")) in candidates
                or ("rva", ref.get("to_rva")) in candidates
                or ("va", ref.get("to_va")) in candidates
                or ("file_offset", ref.get("to_file_offset")) in candidates
            ):
                refs.append(ref)
        return refs

    def get_xrefs_from(self, ea, include_fallthrough=False):
        """
        Return code xrefs originating from a single instruction.
        :param ea:
        :param include_fallthrough:
        :return:
        """
        instruction = self.get_instruction(ea)
        if not instruction:
            return []
        return self._instruction_xrefs(instruction, include_fallthrough=include_fallthrough)

    def get_xrefs_to(self, ea, start=0, end=None, include_fallthrough=False):
        """
        Return code xrefs targeting a specific offset.
        :param ea:
        :param start:
        :param end:
        :param include_fallthrough:
        :return:
        """
        return [
            ref for ref in self.get_code_xrefs(start=start, end=end, include_fallthrough=include_fallthrough)
            if ref["to"] == ea
        ]

    def get_calls_from(self, func):
        """
        Return direct call targets from a recovered function.
        :param func:
        :return:
        """
        function = self._normalize_function(func)
        if not function:
            return []
        return list(function.get("calls_from", []))

    def get_callers(self, func, start=0, end=None):
        """
        Return recovered functions that directly call the provided function.
        :param func:
        :param start:
        :param end:
        :return:
        """
        function = self._normalize_function(func)
        if not function:
            return []
        callers = []
        target = function["start_ea"]
        for candidate in self.find_functions(start=start, end=end):
            if target in candidate.get("calls_from", []):
                callers.append(candidate["start_ea"])
        return callers

    def get_call_graph(self, start=0, end=None):
        """
        Return a simple call graph over recovered functions.
        :param start:
        :param end:
        :return:
        """
        functions = self.find_functions(start=start, end=end)
        function_starts = {function["start_ea"] for function in functions}
        nodes = []
        edges = []
        for function in functions:
            nodes.append({
                "start_ea": function["start_ea"],
                "end_ea": function["end_ea"],
                "size": function["size"],
                "instruction_count": function["instruction_count"],
            })
            for target in function.get("calls_from", []):
                if target in function_starts:
                    edges.append({
                        "from": function["start_ea"],
                        "to": target,
                    })
        return {
            "nodes": nodes,
            "edges": edges,
        }

    def find_calls_to_import(self, import_name, start=0, end=None, case_sensitive=False):
        """
        Find call instructions that reference a specific imported symbol.
        :param import_name:
        :param start:
        :param end:
        :param case_sensitive:
        :return:
        """
        if not import_name:
            return []
        needle = import_name if case_sensitive else import_name.lower()
        matches = []
        for instruction in self._collect_analysis_instructions(start=start, end=end):
            symbol = instruction.get("import_name")
            if not symbol:
                continue
            haystack = symbol if case_sensitive else symbol.lower()
            if needle in haystack:
                function = self.get_function(instruction["address"])
                matches.append({
                    "address": instruction["address"],
                    "import_name": symbol,
                    "function": function["start_ea"] if function else None,
                })
        return matches

    def find_string_references(self, query, exact=False, case_sensitive=False, start=0, end=None):
        """
        Find data references to strings matching a query.
        :param query:
        :param exact:
        :param case_sensitive:
        :param start:
        :param end:
        :return:
        """
        if not query:
            return []
        needle = query if case_sensitive else query.lower()
        matches = []
        for ref in self.get_data_xrefs(start=start, end=end):
            if ref["type"] != "string":
                continue
            label = ref["label"]
            string_entry = self._get_string_lookup()["analysis"].get(ref["to"])
            if not string_entry:
                continue
            haystacks = [string_entry["string"], label]
            if not case_sensitive:
                haystacks = [value.lower() for value in haystacks]
            found = needle in haystacks if exact else any(needle in value for value in haystacks)
            if found:
                matches.append({
                    "from": ref["from"],
                    "string": string_entry["string"],
                    "label": label,
                    "to": ref["to"],
                })
        return matches

    def find_instruction_pattern(self, pattern, start=0, end=None, case_sensitive=False):
        """
        Find instructions or mnemonic sequences matching a pattern.
        :param pattern:
        :param start:
        :param end:
        :param case_sensitive:
        :return:
        """
        instructions = self._collect_analysis_instructions(start=start, end=end)
        if isinstance(pattern, str):
            needle = pattern if case_sensitive else pattern.lower()
            matches = []
            for instruction in instructions:
                haystack = instruction["text"] if case_sensitive else instruction["text"].lower()
                if needle in haystack:
                    matches.append(instruction["address"])
            return matches
        if isinstance(pattern, (list, tuple)) and pattern:
            sequence = list(pattern if case_sensitive else [item.lower() for item in pattern])
            mnemonics = [insn["mnemonic"] if case_sensitive else insn["mnemonic"].lower() for insn in instructions]
            matches = []
            window = len(sequence)
            for index in range(0, len(mnemonics) - window + 1):
                if mnemonics[index:index + window] == sequence:
                    matches.append({
                        "start": instructions[index]["address"],
                        "end": instructions[index + window - 1]["address"],
                        "length": window,
                    })
            return matches
        return []

    def find_functions_by_import_usage(self, import_name, case_sensitive=False):
        """
        Find recovered functions that reference a specific import.
        :param import_name:
        :param case_sensitive:
        :return:
        """
        function_starts = set()
        for match in self.find_calls_to_import(import_name, case_sensitive=case_sensitive):
            if match["function"] is not None:
                function_starts.add(match["function"])
        return sorted(function_starts)

    def find_functions_by_string_reference(self, query, exact=False, case_sensitive=False):
        """
        Find recovered functions that reference matching strings.
        :param query:
        :param exact:
        :param case_sensitive:
        :return:
        """
        function_starts = set()
        for match in self.find_string_references(query, exact=exact, case_sensitive=case_sensitive):
            function = self.get_function(match["from"])
            if function:
                function_starts.add(function["start_ea"])
        return sorted(function_starts)

    def _get_block_successors(self, instruction, block_starts):
        """
        Return successor block starts for a terminating instruction.
        :param instruction:
        :param block_starts:
        :return:
        """
        successors = []
        if instruction["mnemonic"] in COND_BRANCH:
            if instruction["target"] in block_starts:
                successors.append(instruction["target"])
            if instruction["fallthrough"] in block_starts:
                successors.append(instruction["fallthrough"])
            return successors
        if instruction["mnemonic"] in BNC:
            if instruction["target"] in block_starts:
                successors.append(instruction["target"])
            for target in instruction.get("resolved_targets", []):
                if target in block_starts:
                    successors.append(target)
            return successors
        if instruction["is_return"]:
            return successors
        if instruction["fallthrough"] in block_starts:
            successors.append(instruction["fallthrough"])
        return successors

    def _build_basic_blocks_from_instructions(self, instructions, base=0):
        """
        Build basic blocks from a structured instruction list.
        :param instructions:
        :param base:
        :return:
        """
        if not instructions:
            return []
        ordered = sorted(instructions, key=lambda insn: insn["address"])
        addr_set = {insn["address"] for insn in ordered}
        leader_set = {ordered[0]["address"]}
        instruction_map = {insn["address"]: insn for insn in ordered}
        for insn in ordered:
            if insn["mnemonic"] in COND_BRANCH:
                if insn["target"] in addr_set:
                    leader_set.add(insn["target"])
                if insn["fallthrough"] in addr_set:
                    leader_set.add(insn["fallthrough"])
            elif insn["mnemonic"] in BNC:
                if insn["target"] in addr_set:
                    leader_set.add(insn["target"])
                for target in insn.get("resolved_targets", []):
                    if target in addr_set:
                        leader_set.add(target)
        leaders = sorted(leader_set)
        leader_index = {leader: idx for idx, leader in enumerate(leaders)}
        blocks = []
        for idx, leader in enumerate(leaders):
            block_instructions = []
            curr_addr = leader
            while curr_addr in instruction_map:
                insn = instruction_map[curr_addr]
                block_instructions.append(insn)
                next_ea = insn["address"] + insn["size"]
                terminates = insn["mnemonic"] in COND_BRANCH or insn["mnemonic"] in BNC or insn["is_return"]
                if terminates or next_ea not in instruction_map or next_ea in leader_set:
                    break
                curr_addr = next_ea
            last_insn = block_instructions[-1]
            block = {
                "start": leader + base,
                "end": last_insn["address"] + last_insn["size"] + base,
                "id": idx,
                "instructions": block_instructions,
                "instruction_count": len(block_instructions),
                "preds": [],
                "succs": self._get_block_successors(last_insn, leader_index),
            }
            blocks.append(block)
        for block in blocks:
            for succ in block["succs"]:
                blocks[leader_index[succ]]["preds"].append(block["start"] - base)
        for block in blocks:
            block["preds"] = sorted(set(addr + base for addr in block["preds"]))
            block["succs"] = sorted(set(addr + base for addr in block["succs"]))
        return blocks

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
                target_addr = self.get_operand_value(addr, 0)
                if isinstance(target_addr, int):
                    addr = target_addr
                    if target_addr in visited:
                        if target_addr in addr_bcc:
                            if addr_bcc[target_addr] is False:
                                addr_bcc[target_addr] = True
                        else:
                            addr_bcc[target_addr] = False
                        status, t_addr = self.get_false_key(addr_bcc)
                        if status:
                            addr = t_addr
                            continue

            elif instr in BCC:
                if self.word(addr) != 0x15ff:
                    cal_addr = self.get_operand_value(addr, 0)
                    if isinstance(cal_addr, int) and instr not in CALL:
                        if cal_addr not in addr_bcc:
                            if cal_addr not in visited:
                                addr_bcc[cal_addr] = False
                        if self.byte(cal_addr - 1) == 0x00:
                            temp_data = self.get_many_bytes(addr + 5, cal_addr - addr - 6)
                            if temp_data:
                                if all(chr(c) in string.printable for c in temp_data):
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
        if isinstance(func, dict):
            function = func
        elif isinstance(func, int):
            function = self.get_function(func)
            if function is None:
                function = self._walk_function(func)
        else:
            function = None
        if not function:
            return None
        return {
            "function": {
                "start_ea": function["start_ea"],
                "end_ea": function["end_ea"],
                "size": function["size"],
                "instruction_count": function["instruction_count"],
            },
            "blocks": function["basic_blocks"],
        }

    def get_basic_blocks(self, start, end, base=0, debug=False):
        """

        :param start:
        :param end:
        :return:
        """
        instructions = self.get_instructions(start, end)
        basic_blocks = self._build_basic_blocks_from_instructions(instructions, base=base)
        if debug:
            print([hex(block["start"]) for block in basic_blocks])
        return basic_blocks


    def fo(self, value):
        """
        Convert virtual address to file on diskcd
        :param value: virtual address
        :return:
        """
        if isinstance(value, int) and self.pe:
            return self.va_to_file_offset(value)
        if isinstance(value, int):
            return value
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
            if len(insn.operands) > n:
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
            if len(insn.operands) > n:
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
        return hashlib.sha256(self._get_binary_data()).hexdigest()

    def get_input_md5(self):
        """
        Return the MD5 hash of the input binary file
        @return: MD5 string or None on error
        """
        return hashlib.md5(self._get_binary_data()).hexdigest()

    def get_many_bytes(self, ea, size):
        """
        Return the specified number of bytes of the program
        @param ea: linear address
        @param size: size of buffer in normal 8-bit bytes
        @return: None on failure
                 otherwise a string containing the read bytes
        """
        if self.pe:
            temp = self.data[ea:ea+size]
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
            return self.data[ea]
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
            tmp = struct.pack("I", self.dword(ea))
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
            tmp = struct.pack("Q", self.qword(ea))
            return struct.unpack("d", tmp)[0]
        except:
            return None

    def _format_render_address(self, value):
        """
        Render an address-like value for text listings.
        :param value:
        :return:
        """
        if value is None:
            return "None"
        return "0x%x" % value

    def _format_instruction_metadata(self, instruction):
        """
        Render instruction metadata fields for text listings.
        :param instruction:
        :return:
        """
        metadata = [
            "rva=%s" % self._format_render_address(instruction.get("rva")),
            "va=%s" % self._format_render_address(instruction.get("va")),
            "file=%s" % self._format_render_address(instruction.get("file_offset")),
        ]
        if instruction.get("target") is not None:
            target_label = self.get_label_for_address(instruction["target"], kind="analysis")
            if target_label:
                metadata.append("target=%s(%s)" % (self._format_render_address(instruction["target"]), target_label))
            else:
                metadata.append("target=%s" % self._format_render_address(instruction["target"]))
        elif instruction.get("resolved_targets"):
            metadata.append(
                "resolved_targets=%s" % [
                    "%s(%s)" % (
                        self._format_render_address(target),
                        self.get_label_for_address(target, kind="analysis") or self._format_render_address(target),
                    )
                    for target in instruction["resolved_targets"][:8]
                ]
            )
        if instruction.get("fallthrough") is not None and (instruction.get("is_call") or instruction.get("is_jump")):
            fallthrough_label = self.get_label_for_address(instruction["fallthrough"], kind="analysis")
            if fallthrough_label:
                metadata.append("fallthrough=%s(%s)" % (self._format_render_address(instruction["fallthrough"]), fallthrough_label))
            else:
                metadata.append("fallthrough=%s" % self._format_render_address(instruction["fallthrough"]))
        if instruction.get("import_name"):
            metadata.append("import=%s" % instruction["import_name"])
        if instruction.get("is_noreturn"):
            metadata.append("noreturn=True")
        for ref in instruction.get("data_refs", []):
            metadata.append("%s=%s" % (ref["type"], ref["label"]))
        for ref in instruction.get("stack_refs", []):
            metadata.append("%s=%s" % (ref["kind"], ref["label"]))
        if instruction.get("constant_operands"):
            metadata.append(
                "const_operands=%s" % {
                    key: self._format_render_address(value) if isinstance(value, int) else value
                    for key, value in instruction["constant_operands"].items()
                }
            )
        if instruction.get("comment"):
            metadata.append("comment=%s" % instruction["comment"])
        repeatable_comment = instruction.get("repeatable_comment")
        if repeatable_comment and repeatable_comment != instruction.get("comment"):
            metadata.append("repeatable_comment=%s" % repeatable_comment)
        return metadata

    def render_instruction(self, item, include_metadata=True):
        """
        Render one instruction as a normalized text line.
        :param item:
        :param include_metadata:
        :return:
        """
        instruction = item if isinstance(item, dict) else self.get_instruction(item)
        if not instruction:
            return None
        text = instruction.get("display_text") or instruction.get("text") or instruction["mnemonic"]
        if not include_metadata:
            return "%s  %-16s  %s" % (
                self._format_render_address(instruction.get("address")),
                instruction.get("bytes_hex"),
                text,
            )
        metadata = self._format_instruction_metadata(instruction)
        return "%s  %-16s  %-48s ; %s" % (
            self._format_render_address(instruction.get("address")),
            instruction.get("bytes_hex"),
            text,
            ", ".join(metadata),
        )

    def get_disassembly_records(self, start=0, end=None):
        """
        Return structured disassembly records for a linear range.
        :param start:
        :param end:
        :return:
        """
        return self.get_instructions(start=start, end=end)

    def disassemble_range(self, start=0, end=None, include_metadata=True):
        """
        Render a linear disassembly range as text.
        :param start:
        :param end:
        :param include_metadata:
        :return:
        """
        lines = []
        for instruction in self.get_disassembly_records(start=start, end=end):
            rendered = self.render_instruction(instruction, include_metadata=include_metadata)
            if rendered:
                lines.append(rendered)
        return "\n".join(lines)

    def disassemble_function(self, func, include_metadata=True, include_block_headers=False):
        """
        Render a recovered function as text.
        :param func:
        :param include_metadata:
        :param include_block_headers:
        :return:
        """
        function = self._normalize_function(func)
        if not function:
            return None
        lines = []
        classification = function.get("classification", {})
        header = "%s: start=%s end=%s size=0x%x type=%s flags=%s" % (
            function.get("label", self._get_function_label(function["start_ea"])),
            self._format_render_address(function["start_ea"]),
            self._format_render_address(function["end_ea"]),
            function["size"],
            classification.get("type", "function"),
            ",".join(classification.get("flags", [])) or "none",
        )
        lines.append(header)
        function_comment = self.get_function_comment(function, repeatable=False)
        function_repeatable_comment = self.get_function_comment(function, repeatable=True)
        if function_comment:
            lines.append("  ; comment: %s" % function_comment)
        if function_repeatable_comment and function_repeatable_comment != function_comment:
            lines.append("  ; repeatable_comment: %s" % function_repeatable_comment)
        if function.get("stack_analysis"):
            stack_analysis = function["stack_analysis"]
            lines.append(
                "  ; stack: frame=%s alloc=0x%x saved=%s locals=%d args=%d" % (
                    stack_analysis["frame_pointer"] if stack_analysis["frame_pointer"] else "none",
                    stack_analysis["stack_allocation"],
                    stack_analysis["saved_registers"],
                    len(stack_analysis["locals"]),
                    len(stack_analysis["arguments"]),
                )
            )
        block_starts = {block["start"]: block for block in function.get("basic_blocks", [])}
        for instruction in function["instructions"]:
            if include_block_headers and instruction["address"] in block_starts:
                block = block_starts[instruction["address"]]
                lines.append(
                    "  ; block id=%d preds=%s succs=%s" % (
                        block["id"],
                        [self._format_render_address(value) for value in block["preds"]],
                        [self._format_render_address(value) for value in block["succs"]],
                    )
                )
            rendered = self.render_instruction(instruction, include_metadata=include_metadata)
            if rendered:
                lines.append("  %s" % rendered)
        return "\n".join(lines)

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
        instruction = self.get_instruction(ea)
        if instruction:
            return instruction["text"]
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
        if len(self.data) > addr >= 0:
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
        if ea is None or ea == self.BADADDR:
            return self.BADADDR
        instruction_starts = self._get_recovered_instruction_starts()
        if instruction_starts:
            index = bisect.bisect_right(instruction_starts, ea)
            if index < len(instruction_starts):
                return instruction_starts[index]
        code = self.data[ea:ea + self.MAX_BYTE_SIZE]
        for (address, size, mnemonic, op_str) in self.md.disasm_lite(code, 0, 1):
            if size:
                return size + ea
            else:
                break
        candidates = self._get_next_head_candidates(ea)
        if candidates:
            best = sorted(candidates, key=lambda item: (-item["score"], item["start"], item["size"]))[0]
            return best["start"]
        return self.BADADDR

    def _get_next_head_candidates(self, ea, window_size=64):
        """
        Build scored successor candidates after an offset.
        :param ea:
        :param window_size:
        :return:
        """
        if ea is None or ea == self.BADADDR or ea >= len(self.data) - 1:
            return []
        window_end = min(len(self.data), ea + max(window_size, self.MAX_BYTE_SIZE) + 1)
        successors = {}
        valid_starts = []
        info_by_start = {}

        for start in range(ea + 1, window_end):
            insn = self._decode_insn(start)
            if not insn:
                continue
            end = start + insn.size
            if end > window_end:
                continue
            successors[start] = end
            valid_starts.append(start)
            info_by_start[start] = {
                "size": insn.size,
                "mnemonic": insn.mnemonic,
            }

        if not valid_starts:
            return []

        start_set = set(valid_starts)
        chain_score = {}
        for start in sorted(valid_starts, reverse=True):
            score = 1
            end = successors[start]
            if end in start_set:
                score += chain_score.get(end, 1)
            chain_score[start] = score

        candidates = []
        for start in valid_starts:
            info = info_by_start[start]
            score = chain_score.get(start, 1)
            if info["mnemonic"] in END:
                score -= 1
            candidates.append({
                "start": start,
                "size": info["size"],
                "score": score,
            })
        return candidates

    def _get_prev_head_candidates(self, ea, window_size=64):
        """
        Build scored predecessor candidates for an instruction start.
        :param ea:
        :param window_size:
        :return:
        """
        if ea is None or ea == self.BADADDR or ea <= 0:
            return []
        window_start = max(0, ea - max(window_size, self.MAX_BYTE_SIZE))
        predecessors = {}
        valid_starts = []
        info_by_start = {}

        for start in range(window_start, ea):
            insn = self._decode_insn(start)
            if not insn:
                continue
            end = start + insn.size
            if end > ea:
                continue
            predecessors.setdefault(end, []).append(start)
            valid_starts.append(start)
            info_by_start[start] = {
                "size": insn.size,
                "mnemonic": insn.mnemonic,
            }

        if ea not in predecessors:
            return []

        chain_score = {}
        for start in sorted(valid_starts):
            best = 1
            for prev_start in predecessors.get(start, []):
                best = max(best, chain_score.get(prev_start, 1) + 1)
            chain_score[start] = best

        candidates = []
        for start in predecessors[ea]:
            info = info_by_start[start]
            score = chain_score.get(start, 1)
            if info["mnemonic"] in END:
                score -= 2
            candidates.append({
                "start": start,
                "size": info["size"],
                "score": score,
            })
        return candidates

    def _get_recovered_prev_head_map(self):
        """
        Return a cached predecessor map over recovered instruction starts.
        :return:
        """
        if self._recovered_prev_head_cache is not None:
            return self._recovered_prev_head_cache
        instruction_starts = self._get_recovered_instruction_starts()
        self._recovered_prev_head_cache = {
            instruction_starts[index]: instruction_starts[index - 1]
            for index in range(1, len(instruction_starts))
        }
        return self._recovered_prev_head_cache

    def _get_recovered_instruction_starts(self):
        """
        Return cached recovered instruction starts.
        :return:
        """
        if self._recovered_instruction_starts_cache is not None:
            return self._recovered_instruction_starts_cache
        self._recovered_instruction_starts_cache = sorted({
            insn["address"]
            for function in self.find_functions()
            for insn in function["instructions"]
        })
        return self._recovered_instruction_starts_cache


    def prev_head(self, ea):
        """
        Get previous defined item (instruction or data) in the program
        @param ea: linear address to start search from
        @param minea: the search will stop at the address
                minea is included in the search range
        @return: BADADDR - no (more) defined items
        """
        prev_map = self._get_recovered_prev_head_map()
        if ea in prev_map:
            return prev_map[ea]
        candidates = self._get_prev_head_candidates(ea)
        if candidates:
            best = max(candidates, key=lambda item: (item["score"], item["size"], item["start"]))
            return best["start"]
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
            temp_data = self.data
        else:
            temp_data = self.data
        if length and strtype == WIDECHAR:
            return temp_data[ea:ea+length][::2]
        elif length and strtype == ASCII:
            temp = temp_data[ea:ea + length]
            return temp.split(b"\x00")[0]
        if strtype == ASCII:
            temp = temp_data[ea:]
            return temp.split(b"\x00")[0]
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
            if ea_addr_index == 0:
                return
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
