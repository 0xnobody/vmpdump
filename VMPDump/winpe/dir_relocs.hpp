#pragma once
#include "nt_headers.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
    // Not "enum class" to ease the casting to uint16_t:4
    enum reloc_type_id 
    {
        rel_based_absolute =          0,
        rel_based_high =              1,
        rel_based_low =               2,
        rel_based_high_low =          3,
        rel_based_high_adj =          4,
        rel_based_ia64_imm64 =        9,
        rel_based_dir64 =             10,
    };

    struct reloc_entry_t
    {
        uint16_t                    offset  : 12;
        uint16_t                    type    : 4;
    };

    struct reloc_block_t
    {
        uint32_t                    base_rva;
        uint32_t                    size_block;
        reloc_entry_t               entries[ 1 ];   // Variable length array


        inline reloc_block_t* get_next() { return ( reloc_block_t* ) ( ( char* ) this + this->size_block ); }
        inline uint32_t num_entries() { return ( reloc_entry_t* ) get_next() - &entries[ 0 ]; }
    };

    struct reloc_directory_t
    {
        reloc_block_t               first_block;
    };
};
#pragma pack(pop)