#pragma once
#include "nt_headers.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
    enum resource_id : uint16_t
    {
        cursor =                    1,
        bitmap =                    2,
        icon =                      3,
        menu =                      4,
        dialog =                    5,
        string =                    6,
        font_dir =                  7,
        font =                      8,
        accelerator =               9,
        rcdata =                    10,
        message_table =             11,
        group_cursor =              12,
        group_icon =                14,
        version =                   16,
        dlg_include =               17,
        plug_play =                 19,
        vxd =                       20,
        ani_cursor =                21,
        ani_icon =                  22,
        html =                      23,
        manifest =                  24,
    };

    template<bool unicode = true> 
    struct resource_directory_string_t
    {
        using char_t = typename std::conditional<unicode, wchar_t, char>::type;

        uint16_t                    length;
        char_t                      name[ 1 ];              // Variable length array
    };

    struct resource_directory_data_t
    {
        uint32_t                    offset_to_data;
        uint32_t                    size;
        uint32_t                    code_page;
        uint32_t                    _pad0;
    };

    struct resource_directory_entry_t
    {
        union
        {
            struct
            {
                uint32_t            offset_name     : 31;
                uint32_t            is_named        : 1;
            };
            uint16_t                identifier;
        };
        uint32_t                    offset          : 31;
        uint32_t                    is_directory    : 1;
    };

    struct resource_directory_desc_t
    {
        uint32_t                    characteristics;
        uint32_t					timedate_stamp;
        ex_version_t                version;
        uint16_t                    num_named_entries;
        uint16_t                    num_id_entries;
        resource_directory_entry_t  entries[ 1 ];           // Variable length array

        inline uint32_t num_entries() { return num_named_entries + num_id_entries; }
    };

    // Contains { Type -> Name -> Lang } directory, nested
    struct resource_directory_t
    {
        resource_directory_desc_t   type_directory;

        template<typename T> inline T* resolve_offset( uint32_t offset ) { return ( T* ) ( ( char* ) this + offset ); }
        inline resource_directory_desc_t* resolve_directory( const resource_directory_entry_t& entry ) { return entry.is_directory ? resolve_offset<resource_directory_desc_t>( entry.offset ) : nullptr; }
        inline resource_directory_data_t* resolve_data( const resource_directory_entry_t& entry ) { return !entry.is_directory ? resolve_offset<resource_directory_data_t>( entry.offset ) : nullptr; }
        inline resource_directory_string_t<true>* resolve_ustring( const resource_directory_entry_t& entry ) { return entry.is_named ? resolve_offset<resource_directory_string_t<true>>( entry.offset_name ) : nullptr; }
        inline resource_directory_string_t<false>* resolve_string( const resource_directory_entry_t& entry ) { return entry.is_named ? resolve_offset<resource_directory_string_t<false>>( entry.offset_name ) : nullptr; }
    };
};
#pragma pack(pop)