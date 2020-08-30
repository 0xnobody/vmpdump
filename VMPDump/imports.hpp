#pragma once
#include <cstdint>
#include <optional>
#include "instruction.hpp"
#include "module_view.hpp"

namespace vmpdump
{
    // Struct that information regarding an obfuscated VMProtect import.
    //
    struct resolved_import
    {
        // The relative virtual address of the import thunk.
        // ie. The address that holds the obfuscated import pointer.
        //
        uint64_t thunk_rva;

        // The effective address of the import target.
        //
        remote_ea_t target_ea;

        // Constructor.
        //
        resolved_import( uint64_t thunk_rva, uintptr_t target_ea )
            : thunk_rva( thunk_rva ), target_ea( target_ea )
        {}
    };

    // Struct that holds import calls and their referenced import.
    //
    struct import_call
    {
        // The relative virtual address of the actual call instruction.
        //
        uint64_t call_rva;

        // The import that the call referenced.
        //
        const resolved_import* import;

        // The number of bytes the stack is adjusted by at the VMP import stub.
        //
        int32_t stack_adjustment;

        // Whether the import is padded with a junk byte immediately following the call.
        //
        bool padded;

        // Whether the import call is actually a JMP.
        //
        bool is_jmp;

        // The instruction that came exactly before the call instruction.
        //
        std::optional<instruction> prev_instruction;

        // Constructor.
        //
        import_call( uint64_t call_rva, const resolved_import* import, int32_t stack_adjustment, bool padded, bool is_jmp, std::optional<instruction> prev_instruction = {} )
            : call_rva( call_rva ), import( import ), stack_adjustment( stack_adjustment ), padded( padded ), is_jmp( is_jmp ), prev_instruction( prev_instruction )
        {}
    };
}