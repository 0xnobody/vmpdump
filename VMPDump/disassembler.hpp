#pragma once
#include <capstone/capstone.h>
#include <vtil/utility>
#include "instruction_stream.hpp"

namespace vmpdump
{
    // Defaults.
    //
    const cs_arch cs_default_arch = CS_ARCH_X86;
    const cs_mode cs_default_mode = CS_MODE_64;

    // Specifies the desired behaviour of the auto disassembler when a jump condition is
    // encountered
    //
    enum disassembler_flags : uint32_t
    {
        // When met with a branch, stop dissassembly.
        //
        disassembler_none = 0,

        // Take all unconditional immediate jumps, ignoring the jump instructions.
        //
        disassembler_take_unconditional_imm = 1 << 0,

        // Take all conditional jumps.
        //
        disassembler_take_conditional = 1 << 1,

        // Skip all conditional jumps.
        //
        disassembler_skip_conditional = 1 << 2,

        // Pass on calls.
        //
        disassembler_pass_calls = 1 << 3,
    };

    // This class provides a very lightweight thread-safe wrapper over capstone.
    //
    class disassembler
    {
    private:
        // The internal handle.
        //
        csh handle;

        // The internal instruction allocation memory.
        //
        cs_insn* insn;


    public:
        // Cannot be copied or moved.
        // Only one disassembler can exist per thread.
        //
        disassembler( const disassembler& ) = delete;
        disassembler( disassembler&& ) = delete;
        disassembler& operator=( const disassembler&& ) = delete;
        disassembler& operator=( disassembler&& ) = delete;

        disassembler( cs_arch arch, cs_mode mode )
        {
            fassert( cs_open( arch, mode, &handle ) == CS_ERR_OK );
            cs_option( handle, CS_OPT_DETAIL, CS_OPT_ON );
            insn = cs_malloc( handle );
        }

        ~disassembler()
        {
            cs_close( &handle );
        }

        // Getter to the handle.
        //
        csh get_handle() const { return handle; }

        cs_insn* get_insn() { return insn; }

        // Singleton to provide a unique disassembler instance for each thread.
        //
        inline static disassembler& get( cs_arch arch = cs_default_arch, cs_mode mode = cs_default_mode)
        {
            thread_local static disassembler instance( arch, mode );

            return instance;
        }

        // Disassembles at the offset from the base, negotating jumps according to the flags.
        // NOTE: The offset is used for the disassembled instructions' addresses.
        // If the number of instructions disassembled exceeds the provided max amount, en empty instruction stream is returned.
        //
        instruction_stream disassemble( uint64_t base, uint64_t offset, disassembler_flags flags = disassembler_take_unconditional_imm, uint64_t max_instructions = -1 );

        // Disassembles at the offset from the base, simply disassembling every instruction in order.
        //
        std::vector<std::unique_ptr<instruction>> disassembly_simple( uint64_t base, uint64_t offset, uint64_t end_rva );
    };
}