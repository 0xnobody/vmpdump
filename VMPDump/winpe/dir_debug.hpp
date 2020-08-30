#pragma once
#include "nt_headers.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
    enum class debug_directory_type_id : uint32_t
    {
        unknown =       0x00000000,
        coff =          0x00000001,
        codeview =      0x00000002,
        fpo =           0x00000003,
        misc =          0x00000004,
        exception =     0x00000005,
        fixup =         0x00000006,
        omap_to_src =   0x00000007,
        omap_from_src = 0x00000008,
        borland =       0x00000009,
        reserved10 =    0x0000000A,
        clsid =         0x0000000B,
        vc_feature =    0x0000000C,
        pogo =          0x0000000D,
        iltcg =         0x0000000E,
        mpx =           0x0000000F,
        repro =         0x00000010,
    };

    struct debug_directory_entry_t
    {
        uint32_t                    characteristics;
        uint32_t					timedate_stamp;
        ex_version_t                version;
        debug_directory_type_id     type;
        uint32_t                    size_raw_data;
        uint32_t                    rva_raw_data;
        uint32_t                    ptr_raw_data;
    };

    struct debug_directory_t
    {
        debug_directory_entry_t     entries[ 1 ];       // Variable length array
    };
};
#pragma pack(pop)