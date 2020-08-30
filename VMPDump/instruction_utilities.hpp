#pragma once
#include <capstone/capstone.h>
#include <vtil/amd64>

namespace vmpdump
{
    // Determines whether or not the register's bases are equal.
    // e.g. RAX == AH, as base( RAX ) == AL, and base( AH ) == AL.
    //
    inline bool register_base_equal( x86_reg first, x86_reg second )
    {
        return vtil::amd64::registers.remap( first, 0, 1 ) == vtil::amd64::registers.remap( second, 0, 1 );
    }
    
    // Gets the register's largest architecture equivalent.
    //
    inline x86_reg get_largest_for_arch( x86_reg reg )
    {
        return vtil::amd64::registers.remap( reg, 0, 8 );
    }
}