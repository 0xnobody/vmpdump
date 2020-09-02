# VMPDump
![](https://raw.githubusercontent.com/0xnobody/vmpdump/master/screenshot.png)

 A dynamic VMP dumper and import fixer, powered by VTIL. Works for VMProtect 3.X x64.

## Before vs After
![](https://raw.githubusercontent.com/0xnobody/vmpdump/master/before.png)
![](https://raw.githubusercontent.com/0xnobody/vmpdump/master/after.png

## Usage
 VMPDump.exe `<Target PID>` `"<Target Module>"` `[-ep=<Entry Point RVA>]` `[-disable-reloc]`

 Arguments:
 * `<Target PID>`: The ID of the target process, in decimal or hex form.
 * `<Target Module>`: The name of the module which should be dumped and fixed. This can be an empty string ("") if the process image module is desired.
 * `[-ep=<Entry Point RVA>]`: An optionally-provided entry-point RVA, in hex form. VMPDump simply overwrites the Entry Point in the optional header with this value.
 * `[-disable-reloc]`: An optional setting to instruct VMPDump to mark that relocs have been stripped in the ouput image, forcing the image to load at the dumped ImageBase. This is useful if runnable dumps are desired.
 
 VMProtect initialization and unpacking must be complete in the target process before running VMPDump. This means it must be at or past the OEP (Original Entry Point).
 The dumped and fixed image will appear in the module directory, under the name <Module Name>.VMPDump.<Module Extension>.

## How It Works
 VMProtect injects stubs for every import call or jmp. These stubs resolve the 'obfuscated' thunk in the `.vmpX` section, and add a fixed constant to 'deobfuscate' it. The calls or jumps themselves are then dispatched with a ret instruction.

 VMPDump scans all executable sections for these stubs, and lifts them to VTIL using the VTIL x64 lifter. Analysis is then performed on these stubs, in order to determine what kind of call must be replaced and what bytes must be overwritten.

 Once all calls have been retrieved, VMPDump then creates a new import table and appends thunks to the existing IAT. The calls to the VMP import stubs are replaced with direct calls to these thunks.

 Note that in mutated routines, there are situations when there are not enough bytes to replace the VMP import stub call with a direct thunk call, as the former is 1 byte larger. In these cases, the section is extended and a stub that jumps to the import thunk is injected. The VMP import stub call is then replaced with a 5-byte relative call or jmp to said injected stub.

## Building
Building in VS is as simple as replacing the include/library directories to VTIL-NativeLifers/VTIL-Core/Keystone/Capstone in the vcxproj.

The project requires C++20.

## Issues and Limitations
 Due to the fact that code sections are linearly scanned, particularily in heavily mutated and obfuscated code, some import stub calls can be skipped and therefore not resolved. However, VMPDump includes workarounds for the majority of VMProtect mutation inconsistencies, so it should produce decent results even in heavily mutated code.
 
 If you encounter this, please make an issue with the relevant information and I'll take a look at it.

## Licence
 Licensed under the GPL-3.0 License. No warranty is provided of any kind.