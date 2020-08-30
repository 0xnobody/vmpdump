#pragma once
#include <vector>
#include <algorithm>
#include <tuple>
#include <string>
#include "pe_image.hpp"

namespace vmpdump
{
    namespace pe_constructor
    {
        // Serializes the given table, returning a tuple of { serialized table bytes, entry offsets, end rva }
        //
        template <typename T>
        std::tuple<std::vector<uint8_t>, std::vector<uint32_t>, uint32_t> serialize_table( const std::vector<T>& table_entries, uint64_t offset_base = 0 )
        {
            // Result vectors.
            //
            std::vector<uint8_t> result_bytes;
            std::vector<uint32_t> result_offsets;

            // Enumerate each table entry.
            //
            for ( const T& entry : table_entries )
            {
                // Push back current offset.
                //
                result_offsets.push_back( result_bytes.size() + offset_base );

                // Fetch a byte vector of the entry's data.
                //
                std::vector<uint8_t> entry_bytes = entry.get_bytes();

                // Add entry bytes to byte vector.
                //
                result_bytes.insert( result_bytes.end(), entry_bytes.begin(), entry_bytes.end() );
            }

            // Return the values.
            //
            return { result_bytes, result_offsets, result_bytes.size() + offset_base };
        }

        // Converts the given virtual image to a raw-byte image.
        //
        pe_image virtual_to_raw_image( pe_image& virtual_image );

        // Determines the RVA at which the last section of the virtual image provided ends.
        //
        uint32_t get_sections_end( pe_image& virtual_image );

        // Adds the given section, denoted by the byte vector, to the raw pe_image.
        //
        pe_image& add_section( pe_image& raw_image, const std::vector<uint8_t>& section, uint32_t va, const std::string& name, win::section_characteristics_t characteristics );
    }
}