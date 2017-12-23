## Description 
capstools is a set of functions that can be used to do basic static analysis of x86/x64 instructions. The tool uses the [Capstone Engine](http://www.capstone-engine.org/) to disassembly binary data. The intent of this project is to be able to traverse binary data/instructions to do basic binary analysis on memory dumps, binary data, etc. The function naming convention is the same as [IDAPython](https://github.com/idapython/src) but only a very _small_ subset of functions have been implemented. 

This project is a work in progress. I'm still fixing errors as I find them.  

## Usage

### Example usage
```
from capstool import CapsTool
data = open("example.bin", "rb").read()
cs = CapsTool(data, 32)
cur_addr = 0

for x in range(0, 32):
    print "0x%x\t%s"  % (cur_addr, cs.get_disasm(cur_addr))
    cur_addr = cs.next_head(cur_addr)    
```
For Portable Executable (PE) files capstool copies the `.text` section into a buffer using [pefile](https://github.com/erocarrera/pefile). capstool does not attempt to convert the relative virtual address (RVA) for offsets. If working with RVAs, a function named `object.fo` (short for file offset) can be used to return the raw address. 

### Output 
```
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
0x30	push 0xc
0x32	push 0x406050
0x37	push 0x406060
0x3c	mov dword ptr [0x40a2e0], eax
0x41	call 0x3f9c
0x46	push 0xe
0x48	pop ebx
0x49	push ebx
0x4a	push 0x406070
0x4f	push 0x406080
0x54	mov dword ptr [0x40a2e4], eax
0x59	call 0x3f84
0x5e	push 0xd
0x60	pop esi
0x61	push esi
0x62	push 0x406090
0x67	push 0x4060a0
```
