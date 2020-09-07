#include "disassembler.hpp"

namespace vmpdump
{
    // Disassembles at the offset from the base, negotating jumps according to the flags.
    // NOTE: The offset is used for the disassembled instructions' addresses.
    // If the number of instructions disassembled exceeds the provided max amount, en empty instruction stream is returned.
    //
    instruction_stream disassembler::disassemble( uint64_t base, uint64_t offset, disassembler_flags flags, uint64_t max_instructions )
    {
        // ea = base + offset
        //
        uint64_t ea = base + offset;

        std::vector<std::shared_ptr<instruction>> instructions;

        size_t size = 0xFFFFFFFFFFFFFFFFull;

        uint64_t i = 0;

        // Helper lambda to exception-wrap the disassebly.
        // This is useful as we may be dealing with invalid instructions which may cause an access violation.
        //
        auto disasm = [&]() -> bool
        {
            __try
            {
                return cs_disasm_iter( handle, ( const uint8_t** )&ea, &size, &offset, insn );
            }
            __except ( 1 ) {}
            return false;
        };

        // While iterative disassembly is successful.
        //
        while ( disasm() )
        {
            // Check max bounds.
            //
            if ( i >= max_instructions )
                return instruction_stream {};
            i++;

            // Construct a self-containing instruction.
            //
            auto ins = std::make_shared<instruction>( insn );

            // Is the instruction a branch?
            //
            if ( ins->is_branch() )
            {
                // If it's unconditional, and we know the destination, and we are specified
                // to follow these types of jumps, do so.
                //
                if ( flags & disassembler_take_unconditional_imm
                     && ins->is_uncond_jmp() && ins->operand( 0 ).type == X86_OP_IMM )
                {
                    // We must set the offset, otherwise the disassembly will be incorrect.
                    //
                    offset = ins->operand( 0 ).imm;

                    // Update actual disassembly pointer.
                    //
                    ea = offset + base;

                    // Don't append the jump to the stream.
                    //
                    continue;
                }

                // Branch not resolved - simply end disassembly.
                //
                break;
            }

            // Is the instruction a call?
            //
            if ( ins->ins.id == X86_INS_CALL )
            {
                // If the pass calls flag is not set, add it and end disassembly.
                //
                if ( !( flags & disassembler_pass_calls ) )
                {
                    instructions.push_back( ins );
                    break;
                }
            }

            // Is the instruction a return?
            //
            if ( ins->ins.id == X86_INS_RET )
            {
                // Add the instruction and end disassembly.
                //
                instructions.push_back( ins );
                break;
            }

            // Add instruction to list.
            //
            instructions.push_back( ins );
        }

        // Return an instruction stream of said instructions.
        //
        return { instructions };
    }


    // Disassembles at the offset from the base, simply disassembling every instruction in order.
    //
    std::vector<std::unique_ptr<instruction>> disassembler::disassembly_simple( uint64_t base, uint64_t offset, uint64_t end_rva )
    {
        // ea = base + offset
        //
        uint64_t ea = base + offset;

        std::vector<std::unique_ptr<instruction>> instructions;

        size_t size = end_rva - offset;

        // While iterative disassembly is successful.
        //
        while ( true )
        {
            // Check if we're within bounds.
            //
            if ( offset >= size )
                break;

            // In case disassembly failed (due to invalid instructions), try to continue by incrementing offset.
            //
            if ( !cs_disasm_iter( handle, ( const uint8_t** )&ea, &size, &offset, insn ) )
            {
                offset++;
                ea++;

                continue;
            }

            instructions.push_back( std::make_unique<instruction>( insn ) );
        }

        return std::move( instructions );
    }
}