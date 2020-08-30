#pragma once
#include "nt_headers.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
    struct runtime_function_t
    {
        uint32_t                    rva_begin;
        uint32_t                    rva_end;
        uint32_t                    rva_unwind_data;
    };

    struct exception_directory_t
	{
        // Length of this array is determined by the size of the directory
        //
        runtime_function_t           functions[ 1 ];
	};
};
#pragma pack(pop)