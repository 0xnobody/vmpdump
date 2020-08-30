#pragma once
#include "nt_headers.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
    struct image_named_import_t
    {
        uint16_t            hint;
        char                name[ 1 ];
    };

    #pragma pack(push, 8)
    struct image_thunk_data_x64_t
    {
        union
        {
            uint64_t        forwarder_string;
            uint64_t        function;
            uint64_t        address;                   // -> image_named_import_t
            struct
            {
                uint64_t    ordinal     : 16;
                uint64_t    _reserved0  : 47;
                uint64_t    is_ordinal  : 1;
            };
        };
    };
    #pragma pack(pop)

    struct image_thunk_data_x86_t
    {
        union
        {
            uint32_t        forwarder_string;
            uint32_t        function;
            uint32_t        address;                   // -> image_named_import_t
            struct
            {
                uint32_t    ordinal     : 16;
                uint32_t    _reserved0  : 15;
                uint32_t    is_ordinal  : 1;
            };
        };
    };

    template<bool x64 = IS_DEF_AMD64,
        typename base_type = typename std::conditional<x64, image_thunk_data_x64_t, image_thunk_data_x86_t>::type>
        struct image_thunk_data_t : base_type {};
    static_assert( sizeof( image_thunk_data_t<false> ) == sizeof( image_thunk_data_x86_t ) &&
                   sizeof( image_thunk_data_t<true> ) == sizeof( image_thunk_data_x64_t ),
                   "Empty structure influenced structure size." );
};
#pragma pack(pop)