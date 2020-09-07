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
        return vtil::amd64::registers.resolve_mapping( first ).base_register == vtil::amd64::registers.resolve_mapping( second ).base_register;
    }
    
    // Gets the register's largest architecture equivalent.
    //
    inline x86_reg get_largest_for_arch( x86_reg reg )
    {
        return vtil::amd64::registers.extend( reg );
    }
}
