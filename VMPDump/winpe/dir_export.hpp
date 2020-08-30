#pragma once
#include "nt_headers.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
    struct export_directory_t
    {
        uint32_t                    characteristics;
        uint32_t					timedate_stamp;
        ex_version_t                version;
        uint32_t                    name;
        uint32_t                    base;
        uint32_t                    num_functions;
        uint32_t                    num_names;
        uint32_t                    rva_functions;
        uint32_t                    rva_names;
        uint32_t                    rva_name_ordinals;
    };
};
#pragma pack(pop)