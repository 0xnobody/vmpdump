#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace vmpdump
{
    struct import_directory
    {
        union
        {
            uint32_t characteristics;
            uint32_t rva_original_first_thunk;
        };
        uint32_t timedate_stamp;
        uint32_t forwarder_chain;
        uint32_t rva_name;
        uint32_t rva_first_thunk;

        inline std::vector<uint8_t> get_bytes() const
        {
            // Allocate result vector.
            //
            std::vector<uint8_t> result;
            result.resize( sizeof( *this ) );

            // Copy data.
            //
            memcpy( result.data(), this, sizeof( *this ) );

            return result;
        }
    };

    struct image_thunk_data_x64
    {
        union
        {
            uint64_t forwarder_string;
            uint64_t function;
            uint64_t address;
            struct
            {
                uint64_t ordinal : 16;
                uint64_t _reserved0 : 47;
                uint64_t is_ordinal : 1;
            };
        };

        inline std::vector<uint8_t> get_bytes() const
        {
            // Allocate result vector.
            //
            std::vector<uint8_t> result;
            result.resize( sizeof( *this ) );

            // Copy data.
            //
            memcpy( result.data(), this, sizeof( *this ) );

            return result;
        }
    };

    struct import_named_import
    {
        uint16_t hint;
        std::string name;

        inline std::vector<uint8_t> get_bytes() const
        {
            // Allocate result vector.
            //
            std::vector<uint8_t> result;
            result.resize( sizeof( hint ) + name.size() + 1 );

            // Copy data.
            //
            memcpy( result.data(), &hint, sizeof( hint ) );
            memcpy( result.data() + sizeof( hint ), name.data(), name.size() );

            return result;
        }
    };

    struct embedded_string
    {
        std::string string;

        inline std::vector<uint8_t> get_bytes() const
        {
            std::vector<uint8_t> result = { string.begin(), string.end() };
            result.push_back( '\0' );

            return result;
        }
    };
}