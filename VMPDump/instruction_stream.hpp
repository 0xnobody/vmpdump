#pragma once
#include <memory>
#include "instruction.hpp"
#include <vtil/arch>

namespace vmpdump
{
    // This class spans over an ordered vector of instructions.
    // It contains an index to determine the current position in the
    // stream.
    //
    class instruction_stream
    {
    public:
        // The backing instruction vector.
        // This is a shared_ptr vector as instruction_streams are copyable
        // and thus instruction objects can have multiple owners.
        //
        std::vector<std::shared_ptr<instruction>> instructions;

    private:
        // Begin index of span.
        //
        uint32_t begin;

        // End index of span.
        //
        uint32_t end;

        // Current Index.
        //
        uint32_t index;

    public:
        // Default constructor / move / copy.
        //
        instruction_stream( instruction_stream&& ) = default;
        instruction_stream( const instruction_stream& ) = default;
        instruction_stream& operator= ( instruction_stream&& ) = default;
        instruction_stream& operator= ( const instruction_stream& ) = default;

        // Construct as empty.
        //
        instruction_stream()
            : instructions{}, begin( 0 ), end( 0 ), index( 0 )
        {}

        // Construct via copying existing instruction vector
        //
        instruction_stream( const std::vector<std::shared_ptr<instruction>>& instructions )
            : instructions( instructions ), begin( 0 ), end( instructions.size() - 1 ), index( 0 )
        {}

        // Get the stream base
        //
        inline uint64_t base() const
        {
            return instructions[ begin ]->ins.address;
        }

        // Disassembler bases instructions via RVA, thus base == rva.
        //
        inline uint64_t rva() const
        {
            return base();
        }

        // Resets index to 0
        //
        inline void reset()
        {
            index = 0;
        }

        // Advances the stream, incrementing index and returning the
        // instruction ptr.
        // Non-owning.
        //
        const instruction* next();

        // Returns a byte vector of all the instructions' bytes.
        //
        std::vector<uint8_t> bytes() const;

        // Lifts the instruction stream to VTIL.
        //
        vtil::basic_block* lift() const;
    };
}