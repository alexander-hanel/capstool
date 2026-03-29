## Description
capstool is a set of functions that can be used to do static analysis of x86/x64 instructions. The tool uses the [Capstone Engine](http://www.capstone-engine.org/) to disassemble binary data. The intent of this project is to be able to traverse binary data/instructions to do binary analysis on memory dumps, PE files, and raw code/data buffers. The function naming convention is similar to [IDAPython](https://github.com/idapython/src), but only a subset of functions have been implemented.

This project is a work in progress. The current focus is automation-oriented reverse engineering for PE x86/x64 binaries.

Disclaimer: newest version was vibe coded...

## Installation

```bash
pip install capstool
```

The package depends on:

- `capstone`
- `pefile`

## Usage

### Example usage

```python
import json
from capstool import CapsTool

data = open("example.bin", "rb").read()
cs = CapsTool(data, 32)
cur_addr = 0

for _ in range(0, 16):
    print("0x%x\t%s" % (cur_addr, cs.get_disasm(cur_addr)))
    cur_addr = cs.next_head(cur_addr)

report = {
    "functions": cs.find_functions(),
    "strings": cs.find_strings(),
    "code_xrefs": cs.get_code_xrefs(include_fallthrough=True),
    "data_xrefs": cs.get_data_xrefs(),
}

with open("report.json", "w", encoding="utf-8") as fp:
    json.dump(report, fp, indent=2, default=lambda value: value.hex() if isinstance(value, bytes) else value)
```

### Portable Executable (PE) files

For PE files capstool copies the `.text` section into an analysis buffer using [pefile](https://github.com/erocarrera/pefile). The library also keeps the original PE image and exposes helpers to move between:

- analysis offsets
- RVAs
- VAs
- file offsets

Example:

```python
from pathlib import Path
import pefile
from capstool import CapsTool

path = Path("sample.exe")
data = path.read_bytes()
pe = pefile.PE(data=data)
bitness = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32

cs = CapsTool(data, bitness)
entry = cs.get_entry_point()

print(entry)
print(cs.analysis_offset_to_rva(entry["analysis_offset"]))
print(cs.analysis_offset_to_va(entry["analysis_offset"]))
print(cs.analysis_offset_to_file_offset(entry["analysis_offset"]))
```

### Output

```text
0x0	push ebp
0x1	mov ebp, esp
0x3	sub esp, 0x34
0x6	push ebx
0x7	push esi
0x8	push edi
0x9	push 3
0xb	push 0x406020
0x10	push 0x406024
0x15	call 0x3fc8
0x1a	push 0x11
0x1c	push 0x406028
0x21	push 0x40603c
0x26	mov dword ptr [0x40a9f8], eax
0x2b	call 0x3fb2
```

## Example script

```python
from pathlib import Path
import pefile
from capstool import CapsTool

path = Path("sample.exe")
data = path.read_bytes()
pe = pefile.PE(data=data)
bitness = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32

cs = CapsTool(data, bitness)

entry = cs.get_entry_point()
print("entry", entry)

first_instruction = cs.get_instruction(entry["analysis_offset"])
print("first instruction", first_instruction["text"])

functions = cs.find_functions()
print("functions", len(functions))

entry_function = cs.get_function(entry["analysis_offset"])
if entry_function is None and functions:
    entry_function = functions[0]

if entry_function:
    print("function label", entry_function["label"])
    print("classification", cs.get_function_classification(entry_function))
    print("stack variables", cs.get_stack_variables(entry_function))
    print("first 3 stack refs", cs.get_stack_references(entry_function)[:3])
    print("data flow blocks", len(cs.get_data_flow(entry_function)["block_states"]))

    entry_addr = entry_function["instructions"][0]["address"]
    cs.comment_ex(entry_addr, comment="entry instruction")
    cs.set_function_comment(entry_function, "example function comment")
    cs.set_label(entry_function["start_ea"], "example_start")

    print("comment", cs.get_comment_ex(entry_addr, 0))
    print("function comment", cs.get_function_comment(entry_function, 0))
    print("label", cs.get_label_for_address(entry_function["start_ea"]))

    print("rendered function")
    print(cs.disassemble_function(entry_function, include_metadata=True))

print("imports", len(cs.get_imports()))
print("sections", cs.get_sections())
print("strings", len(cs.find_strings()))
print("call graph", cs.get_call_graph())
print("code xrefs", len(cs.get_code_xrefs(include_fallthrough=True)))
print("data xrefs", len(cs.get_data_xrefs()))
print("calls to ExitProcess", cs.find_calls_to_import("ExitProcess"))
print("pattern matches", cs.find_instruction_pattern(["push", "mov", "sub"])[:5])
```

## API reference

The methods below are the current public API surface. Private helper methods beginning with `_` are intentionally omitted.

### Construction and metadata

- `CapsTool(data, bit=32)`: create a disassembly/analysis object.
- `get_input_sha256()`: return the SHA-256 hash of the input buffer.
- `get_input_md5()`: return the MD5 hash of the input buffer.
- `get_pe_metadata()`: return high-level PE metadata.
- `get_sections()`: return PE section metadata.
- `get_entry_point()`: return entry-point metadata.
- `get_imports()`: return PE imports.
- `get_exports()`: return PE exports.

### Address conversion

- `analysis_offset_to_rva(value)`: convert analysis offset to RVA.
- `analysis_offset_to_va(value)`: convert analysis offset to VA.
- `analysis_offset_to_file_offset(value)`: convert analysis offset to file offset.
- `rva_to_analysis_offset(value)`: convert RVA to analysis offset.
- `va_to_analysis_offset(value)`: convert VA to analysis offset.
- `rva_to_file_offset(value)`: convert RVA to file offset.
- `file_offset_to_rva(value)`: convert file offset to RVA.
- `va_to_file_offset(value)`: convert VA to file offset.
- `file_offset_to_va(value)`: convert file offset to VA.
- `get_address_info(value, kind="analysis")`: normalize an address in the analysis space.
- `get_binary_address_info(value, kind="analysis")`: normalize an address anywhere in the input image.
- `fo(value)`: convert VA to file offset for PE inputs.

### Raw reads and scalar helpers

- `get_many_bytes(ea, size)`: read a byte range.
- `byte(ea)`: read one byte.
- `word(ea)`: read a 16-bit value.
- `dword(ea)`: read a 32-bit value.
- `qword(ea)`: read a 64-bit value.
- `get_float(ea)`: read a 32-bit IEEE float.
- `get_double(ea)`: read a 64-bit IEEE double.
- `get_strlit_contents(ea, length=None, strtype=ASCII)`: read ASCII or UTF-16LE string contents from the analysis buffer.

### Instruction decoding

- `get_instruction(ea)`: return one structured instruction dictionary.
- `get_instructions(start=0, end=None, max_instructions=MAX_INSTRU)`: return a linear list of structured instructions.
- `get_disasm(ea)`: return one disassembly line.
- `get_disasm_ex(ea, flags=0)`: return one annotated disassembly line.
- `get_mnem(ea)`: return the mnemonic at `ea`.
- `get_operand_value(ea, n)`: return operand value information.
- `get_operand_type(ea, n)`: return operand type information.

### Navigation helpers

- `next_addr(ea)`: move to the next byte.
- `prev_addr(ea)`: move to the previous byte.
- `next_head(ea)`: move to the next recovered instruction head.
- `prev_head(ea)`: move to the previous recovered instruction head.
- `dis_addr(addr, bit, debug=False)`: recursively walk code from an address.

### Functions and control flow

- `find_functions(start=0, end=None)`: recover likely functions.
- `get_function(ea)`: return the recovered function containing an address.
- `get_function_classification(func)`: return function classification metadata.
- `get_basic_blocks(start, end, base=0, debug=False)`: recover basic blocks in a range.
- `flowchart(func)`: return a flowchart object for a function.
- `get_call_graph(start=0, end=None)`: return a simple call graph.
- `get_calls_from(func)`: return direct call targets from a function.
- `get_callers(func, start=0, end=None)`: return functions that call a target function.

### Code and data references

- `get_code_xrefs(start=0, end=None, include_fallthrough=False)`: return code xrefs.
- `get_xrefs_from(ea, include_fallthrough=False)`: return code xrefs from one instruction.
- `get_xrefs_to(ea, start=0, end=None, include_fallthrough=False)`: return code xrefs to one target.
- `get_data_xrefs(start=0, end=None)`: return data/string/import references.
- `get_data_xrefs_from(ea)`: return data refs from one instruction.
- `get_data_xrefs_to(value, kind="auto", start=0, end=None)`: return refs to one data target.

### Strings, labels, comments, and symbols

- `find_strings(min_length=4, include_ascii=True, include_wide=True)`: recover strings from the full input image.
- `get_label_for_address(value, kind="auto")`: resolve the best label for an address-like value.
- `set_label(value, label, kind="analysis")`: set or clear a user-defined label.
- `get_label(value, kind="analysis")`: return a user-defined label.
- `get_symbols(include_auto=False)`: return user and optional auto-generated symbols.
- `set_comment(ea, comment, repeatable=False)`: set or clear an instruction/data comment.
- `get_comment(ea, repeatable=False)`: get an instruction/data comment.
- `get_comment_ex(ea, repeatable)`: IDA-like comment getter.
- `comment_ex(ea, repeatable=0, comment=None)`: IDA-like comment getter/setter convenience wrapper.
- `set_function_comment(func, comment, repeatable=False)`: set or clear a function comment.
- `get_function_comment(func, repeatable=False)`: get a function comment.

### Stack and data-flow analysis

- `get_stack_references(func)`: return stack references for a recovered function.
- `get_stack_variables(func)`: return recovered locals, arguments, saved registers, and stack allocation.
- `get_data_flow(func)`: return lightweight constant-propagation data for a function.
- `get_register_constants_at(func, ea, when="in")`: return register constants before or after an instruction.

### Search and matching helpers

- `find_calls_to_import(import_name, start=0, end=None, case_sensitive=False)`: search for import calls.
- `find_string_references(query, exact=False, case_sensitive=False, start=0, end=None)`: search for string references.
- `find_instruction_pattern(pattern, start=0, end=None, case_sensitive=False)`: search by disassembly substring or mnemonic sequence.
- `find_functions_by_import_usage(import_name, case_sensitive=False)`: return functions that use a specific import.
- `find_functions_by_string_reference(query, exact=False, case_sensitive=False)`: return functions that reference matching strings.

### Rendering helpers

- `render_instruction(item, include_metadata=True)`: render one instruction line.
- `get_disassembly_records(start=0, end=None)`: return structured disassembly records.
- `disassemble_range(start=0, end=None, include_metadata=True)`: render a linear range.
- `disassemble_function(func, include_metadata=True, include_block_headers=False)`: render one recovered function.

### Utility helpers

- `to_signed_32(n)`: convert an integer to signed 32-bit form.
- `to_signed_64(n)`: convert an integer to signed 64-bit form.
- `get_op_dist(bit, addr)`: return signed branch/call operand distance when possible.
- `get_false_key(addr_bcc)`: helper used by recursive traversal.

## Notes

- The current analysis is focused on x86 and x86-64.
- PE analysis is the most complete path right now.
- Function recovery, indirect-branch recovery, and data-flow are heuristic and intended for automation, not for perfect lifting/decompilation.
