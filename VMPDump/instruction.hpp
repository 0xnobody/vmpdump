#pragma once
#include <capstone/capstone.h>
#include <memory>
#include <vector>

namespace vmpdump
{
    // This class provides a simple wrapper over the cs_insn and cs_detail
    // structs to make it self-containing, and to provide some simple utilities.
    //
    class instruction
    {
    private:
        // This is an internal backing structure that the cs_insn->detail
        // points to.
        //
        cs_detail detail;

    public:
        // The wrapped instruction.
        //
        cs_insn ins;

        // Copy constructor.
        //
        instruction( const cs_insn* ins )
            : ins( *ins ), detail( *ins->detail )
        {
            // Point ins->detail to copy.
            //
            this->ins.detail = &detail;
        }

        // Determines whether this instruction is any type of jump.
        //
        bool is_jmp() const;

        // Useful utilities.
        //
        inline int                 operand_count()         const { return detail.x86.op_count; }
        inline const cs_x86_op&    operand( int i )        const { return detail.x86.operands[ i ]; }
        inline x86_op_type         operand_type( int i )   const { return detail.x86.operands[ i ].type; }

        inline bool                is_uncond_jmp()         const { return ins.id == X86_INS_JMP; };

        inline bool                is_branch()             const { return is_jmp(); }

        inline x86_prefix          prefix( int i )         const { return ( x86_prefix )detail.x86.prefix[ i ]; }

        // Returns a vector of registers this instruction writes to and reads from.
        // Read is returned in the first part of the pair, Written in the second.
        //
        std::pair<std::vector<x86_reg>, std::vector<x86_reg>> get_regs_accessed() const;

        // Is the instruction a conditional jump?
        //
        bool is_cond_jump() const;
    };
}