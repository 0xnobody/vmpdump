#include "instruction.hpp"
#include "disassembler.hpp"

namespace vmpdump
{
    // Determines whether this instruction is any type of jump.
    //
    bool instruction::is_jmp() const
    {
        // Enumerate instruction groups.
        //
        for ( int i = 0; i < ins.detail->groups_count; i++ )
        {
            auto grp = ins.detail->groups[ i ];

            // If group is JMP, return true.
            //
            if ( grp == X86_GRP_JUMP )
                return true;
        }

        return false;
    }

    // Is the instruction a conditional jump?
    //
    bool instruction::is_cond_jump() const
    {
        // Return false if unconditional.
        //
        if ( ins.id == X86_INS_JMP )
            return false;

        // Loop through groups.
        //
        for ( int i = 0; i < ins.detail->groups_count; i++ )
        {
            if ( ins.detail->groups[ i ] == X86_GRP_JUMP )
                return true;
        }

        return false;
    }

    // Returns a vector of registers this instruction writes to and reads from.
    // Read is returned in the first part of the pair, Written in the second.
    //
    std::pair<std::vector<x86_reg>, std::vector<x86_reg>> instruction::get_regs_accessed() const
    {
        // Declare C-arrays of the data.
        //
        cs_regs read, write;
        uint8_t readc, writec;

        // Use capstone to get lists of registers read from / written to.
        //
        if ( cs_regs_access( disassembler::get().get_handle(), &ins, read, &readc, write, &writec ) != CS_ERR_OK )
            return {};

        std::vector<x86_reg> read_vec, write_vec;

        // Convert raw C style arrays to pretty C++ vectors.
        //
        for ( int i = 0; i < readc; i++ )
            read_vec.push_back( ( x86_reg )read[ i ] );
        for ( int i = 0; i < writec; i++ )
            write_vec.push_back( ( x86_reg )write[ i ] );

        return { read_vec, write_vec };
    }
}