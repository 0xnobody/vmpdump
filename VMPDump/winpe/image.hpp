#pragma once
#include "nt_headers.hpp"

#include "dir_debug.hpp"
#include "dir_exceptions.hpp"
#include "dir_export.hpp"
#include "dir_iat.hpp"
#include "dir_import.hpp"
#include "dir_relocs.hpp"
#include "dir_tls.hpp"
#include "dir_load_config.hpp"
#include "dir_resource.hpp"

// TODO:
// - Implement security directory
// - Implement parsing helpers
namespace win
{
	// Image wrapper
	//
	template<bool x64 = IS_DEF_AMD64>
	struct image_t
	{
		dos_header_t				dos_header;
		
		inline operator dos_header_t&() { return dos_header; }
		inline dos_header_t& get_dos_headers() { return dos_header; }

		inline nt_headers_t<x64>* get_nt_headers() { return dos_header.get_nt_headers<x64>(); }

		inline uint32_t compete_checksum( uint32_t file_len )
		{
			// Calculate partial sum
			uint32_t psum_tmp = 0;
			uint16_t* raw_data = ( uint16_t* ) &dos_header;
			for ( uint32_t off = 0; off < ( file_len + 1 ) >> 1; off++ )
			{
				// Add uint16_t
				psum_tmp += raw_data[ off ];
				// If it overflows, increment by one
				psum_tmp = ( psum_tmp >> 16 ) + ( psum_tmp & 0xFFFF );
			}
			uint16_t partial_sum = psum_tmp;

			// Adjust for the previous .checkum field (=0)
			uint16_t* adjust_sum = ( uint16_t* ) &get_nt_headers()->optional_header.checksum;
			for ( int i = 0; i < 2; i++ )
			{
				// If it underflows, decrement by one
				partial_sum -= partial_sum < adjust_sum[ i ];
				// Substract uint16_t
				partial_sum -= adjust_sum[ i ];
			}

			// Return result
			return ( uint32_t ) partial_sum + file_len;
		}

		inline data_directory_t* get_directory( directory_id id )
		{
			auto nt_hdrs = get_nt_headers();
			if ( nt_hdrs->optional_header.num_data_directories <= id ) return nullptr;
			data_directory_t* dir = &nt_hdrs->optional_header.data_directories.entries[ id ];
			return dir->present() ? dir : nullptr;
		}

		template<typename T = void>
		inline T* rva_to_ptr( uint32_t rva )
		{
			auto nt_hdrs = get_nt_headers();
			if ( !rva || nt_hdrs->optional_header.size_image <= rva ) return nullptr;

			uint8_t* output = rva + ( uint8_t* ) &dos_header;
			for ( int i = 0; i < nt_hdrs->file_header.num_sections; i++ )
			{
				auto section = nt_hdrs->get_section( i );
				if ( section->virtual_address <= rva && rva < ( section->virtual_address + section->virtual_size ) )
				{
					output = output - section->virtual_address + section->ptr_raw_data;
					break;
				}
			}

			return ( T* ) output;
		}

		inline section_header_t* rva_to_section( uint32_t rva )
		{
			auto nt_hdrs = get_nt_headers();
			if ( !rva || nt_hdrs->optional_header.size_image <= rva ) return nullptr;

			uint8_t* output = rva + ( uint8_t* ) &dos_header;
			for ( int i = 0; i < nt_hdrs->file_header.num_sections; i++ )
			{
				auto section = nt_hdrs->get_section( i );
				if ( section->virtual_address <= rva && rva < ( section->virtual_address + section->virtual_size ) )
				{
					return section;
				}
			}

			return nullptr;
		}
	};
	using image_x64_t = image_t<true>;
	using image_x86_t = image_t<false>;
};