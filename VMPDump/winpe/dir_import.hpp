#pragma once
#include "nt_headers.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
    struct import_directory_t
    {
        union
        {
            uint32_t                characteristics;                // 0 for terminating null import descriptor
            uint32_t                rva_original_first_thunk;       // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        };
        uint32_t					timedate_stamp;                 // 0 if not bound,
                                                                    // -1 if bound, and real date\time stamp
                                                                    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                                                    // O.W. date/time stamp of DLL bound to (Old BIND)

        uint32_t                    forwarder_chain;                // -1 if no forwarders
        uint32_t                    rva_name;
        uint32_t                    rva_first_thunk;                // RVA to IAT (if bound this IAT has actual addresses)
    };
};
#pragma pack(pop)