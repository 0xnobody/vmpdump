#include "instruction_stream.hpp"
#include <lifters/core>
#include <lifters/amd64>

namespace vmpdump
{
    // Advances the stream, incrementing index and returning the
    // instruction ptr.
    //
    const instruction* instruction_stream::next()
    {
        // Check if within bounds.
        //
        if ( begin + index > end )
            return nullptr;

        // Fetch instruction.
        //
        auto& ins = instructions[ begin + index ];

        // Increment index.
        //
        index++;

        // Return a non-owning pointer to the instruction.
        //
        return ins.get();
    }

    // Returns a byte vector of all the instructions' bytes.
    //
    std::vector<uint8_t> instruction_stream::bytes() const
    {
        std::vector<uint8_t> result;

        // Enumerate through each instruction.
        //
        for ( int i = begin; i <= end; i++ )
        {
            auto& ins = instructions[ i ];

            result.insert( result.end(), &ins->ins.bytes[ 0 ], &ins->ins.bytes[ 0 ] + ins->ins.size );
        }

        return result;
    }

    // Lifts the instruction stream to VTIL.
    //
    vtil::basic_block* instruction_stream::lift() const
    {
        using namespace vtil;

        // Create a new basic block.
        //
        basic_block* block = basic_block::begin( 0 );

        // We are lifting a raw instruction stream; we don't need to preserve anything.
        //
        block->owner->routine_convention = {};
        block->owner->routine_convention.purge_stack = true;

        // Instansiate the lifter.
        //
        lifter::amd64::lifter_t lifter;

        // Enumerate through each instruction.
        //
        for ( int i = begin; i <= end; i++ )
        {
            auto& ins = instructions[ i ];

            // Lift the single instruction.
            //
            lifter.process( block, ins->ins.address, ins->ins.bytes );
        }

        // Return the created basic block.
        //
        return block;
    }
}