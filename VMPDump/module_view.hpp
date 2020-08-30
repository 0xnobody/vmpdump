#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <variant>
#include <optional>
#include <string>
#include "pe_image.hpp"

namespace vmpdump
{
    // A remote process effective address.
    //
    using remote_ea_t = uintptr_t;

    // Identifies an export within a module.
    //
    using export_id_t = std::pair<std::string, uint32_t>;

    // This class allows provides easy remote module read + write capabilities.
    //
    struct module_view
    {
        // The target process id.
        //
        const uint32_t process_id;

        // The name of the target module, or empty if not available.
        //
        const std::string module_name;

        // The base of the remote module in the target process.
        //
        const remote_ea_t module_base;

        // The virtual size of the module.
        //
        const size_t module_size;

        // The locally copied module.
        //
        pe_image local_module;
        
        // Determined whether the provided remote ea is within module bounds.
        //
        inline bool within_bounds( remote_ea_t ea ) const
        {
            return ea >= module_base && ea < module_base + module_size;
        }

        // Commits any local module changes back to the target process.
        //
        bool commit() const;

        // Fetches any remote module changes back to the local module buffer.
        //
        bool fetch();

        // Returns the export name (if available) and ordinal.
        //
        std::optional<export_id_t> get_export( remote_ea_t ea );

        // Constructor, automatically fetching the remote module's bytes.
        //
        module_view( uint32_t process_id, const std::string& module_name, remote_ea_t module_base, size_t module_size )
            : process_id( process_id ), module_name( module_name ), module_base( module_base ), module_size( module_size )
        {
            fetch();
        }

        // Constructor.
        //
        module_view( uint32_t process_id, const std::string& module_name, remote_ea_t module_base, size_t module_size, const pe_image& local_module )
            : process_id( process_id ), module_name( module_name ), module_base( module_base ), module_size( module_size ), local_module( local_module )
        {}
    };
}