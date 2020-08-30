#include "pe_constructor.hpp"
#include <algorithm>

namespace vmpdump
{
    namespace pe_constructor
    {
        // Converts the given virtual image to a raw-byte image.
        //
        pe_image virtual_to_raw_image( pe_image& virtual_image )
        {
            using namespace win;

            std::vector<uint8_t>& virtual_raw_bytes = virtual_image.raw_bytes;
            image_x64_t* img = virtual_image.get_image();
            nt_headers_x64_t* nt = img->get_nt_headers();

            std::vector<uint8_t> raw_bytes;

            // Copy headers.
            //
            raw_bytes.insert( raw_bytes.end(), virtual_raw_bytes.begin(), virtual_raw_bytes.begin() + nt->optional_header.size_headers );

            uint32_t section_alignment = nt->optional_header.section_alignment;

            // Copy each section.
            // We are using virtual addressing here on purpose, as in packed VMP files the raw data is NULL.
            //
            for ( int i = 0; i < nt->file_header.num_sections; i++ )
            {
                section_header_t* section = nt->get_section( i );

                // Determine aligned section end.
                //
                uint32_t section_end = section->virtual_address + section->virtual_size;
                uint32_t required_alignment = section_alignment - ( section_end % section_alignment );

                // Resize vector if required.
                //
                if ( raw_bytes.size() < section_end + required_alignment )
                    raw_bytes.resize( section_end + required_alignment );

                // Copy section bytes.
                //
                std::copy( virtual_raw_bytes.begin() + section->virtual_address, virtual_raw_bytes.begin() + section->virtual_address + section->virtual_size, raw_bytes.begin() + section->virtual_address );
            }
            
            // Construct the raw image.
            //
            pe_image raw_image = { raw_bytes };
            image_x64_t* raw_img = raw_image.get_image();
            nt_headers_x64_t* raw_nt = raw_img->get_nt_headers();

            // Copy virtual addresses to raw addresses.
            //
            for ( int i = 0; i < raw_nt->file_header.num_sections; i++ )
            {
                section_header_t* section = raw_nt->get_section( i );

                uint32_t required_alignment = section_alignment - ( section->virtual_size % section_alignment );

                section->ptr_raw_data = section->virtual_address;
                section->size_raw_data = section->virtual_size + required_alignment;
            }

            return raw_image;
        }

        // Determines the RVA at which the last section of the virtual image provided ends.
        //
        uint32_t get_sections_end( pe_image& virtual_image )
        {
            using namespace win;

            image_x64_t* img = virtual_image.get_image();
            nt_headers_x64_t* nt = img->get_nt_headers();

            uint32_t highest_section_end = 0;

            // Enumerate each section.
            //
            for ( int i = 0; i < nt->file_header.num_sections; i++ )
            {
                section_header_t* section = nt->get_section( i );

                uint32_t required_alignment = nt->optional_header.section_alignment - ( section->virtual_size % nt->optional_header.section_alignment );

                uint32_t section_end = section->virtual_address + section->virtual_size + required_alignment;

                if ( section_end > highest_section_end )
                    highest_section_end = section_end;
            }

            return highest_section_end;
        }

        // Adds the given section, denoted by the byte vector, to the raw pe_image.
        //
        pe_image& add_section( pe_image& raw_image, const std::vector<uint8_t>& section, uint32_t va, const std::string& name, win::section_characteristics_t characteristics )
        {
            using namespace win;

            uint32_t file_alignment = raw_image.get_image()->get_nt_headers()->optional_header.file_alignment;
            uint32_t section_alignment = raw_image.get_image()->get_nt_headers()->optional_header.section_alignment;
            uint32_t required_raw_alignment = file_alignment - ( section.size() % file_alignment );
            uint32_t required_section_alignment = section_alignment - ( section.size() % section_alignment );

            // Create new section header.
            //
            section_header_t new_section = {};
            memcpy( &new_section.name, name.data(), name.size() >= LEN_SECTION_NAME ? LEN_SECTION_NAME - 1 : name.size() );
            new_section.virtual_size = section.size();
            new_section.virtual_address = va;
            new_section.size_raw_data = section.size() + required_raw_alignment;
            new_section.ptr_raw_data = raw_image.size();
            new_section.characteristics = characteristics;

            // Add new section to raw buffer.
            //
            raw_image.raw_bytes.insert( raw_image.raw_bytes.end(), section.begin(), section.end() );
            raw_image.raw_bytes.resize( raw_image.raw_bytes.size() + required_raw_alignment );

            image_x64_t* img = raw_image.get_image();
            nt_headers_x64_t* nt = img->get_nt_headers();

            // Copy new section.
            //
            // TODO: verify that we can fit in another section in the headers, and if we can't, increase
            // header size and relocate the rest of the image!
            //
            *nt->get_section( nt->file_header.num_sections ) = new_section;

            // Increment number of sections.
            //
            nt->file_header.num_sections++;

            // Write new SizeOfImage if required.
            //
            if ( nt->optional_header.size_image < new_section.virtual_address + new_section.virtual_size )
                nt->optional_header.size_image = new_section.virtual_address + new_section.virtual_size + required_section_alignment;

            return raw_image;
        }
    }
}