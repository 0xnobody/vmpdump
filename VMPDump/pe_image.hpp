#pragma once
#include <vector>
#include "winpe/image.hpp"

namespace vmpdump
{
	// Describes a 64/32 bit Microsoft Portable Executable Image.
	//
	struct pe_image
	{
		// Construct by raw byte array.
		//
		std::vector<uint8_t> raw_bytes;
		pe_image( const std::vector<uint8_t>& raw_bytes = {} ) : raw_bytes( raw_bytes ) {}

		// Default move/copy.
		//
		pe_image( pe_image&& ) = default;
		pe_image( const pe_image& ) = default;
		pe_image& operator=( pe_image&& ) = default;
		pe_image& operator=( const pe_image& ) = default;

		inline uint8_t* data() { return raw_bytes.data(); }
		inline const uint8_t* cdata() const { return raw_bytes.data(); }
		inline size_t size() const { return raw_bytes.size(); }

		inline win::image_t<true>* get_image() { return ( win::image_t<true>* )data(); }
	};
}