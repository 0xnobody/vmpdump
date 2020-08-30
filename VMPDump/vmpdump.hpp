#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <optional>
#include <memory>
#include <vector>
#include <map>
#include "imports.hpp"
#include "module_view.hpp"

namespace vmpdump
{
    // The master class allowing for easy access to all dumper and import reconstruction functionality.
    //
    class vmpdump
    {
    public:
        // The target process' id.
        //
        const uint32_t process_id;
        
        // A map of { module base, { module name, module size> }.
        //
        const std::map<remote_ea_t, std::pair<std::string, size_t>> process_modules;

        // A view to the target module for dumping.
        //
        std::unique_ptr<module_view> const target_module_view;

        // The full path to the target module.
        //
        const std::string module_full_path;

        // Disallow construction + copy.
        //
        vmpdump() = delete;
        vmpdump( const vmpdump& ) = delete;
        vmpdump& operator=( const vmpdump& ) = delete;
        
        // Allow move.
        //
        vmpdump( vmpdump&& ) = default;
        vmpdump& operator=( vmpdump&& ) = default;

        // Scans the specified code range for any import calls and imports.
        // resolved_imports is a map of { import thunk rva, import structure }.
        //
        bool scan_for_imports( uint64_t rva, size_t code_size, std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t flags = 0 );

        // Scans all executable sections of the image for any import calls and imports.
        //
        bool scan_for_imports( std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t flags = 0 );

        // Attempts to generate a stub in a code cave in the section of the call rva which jmps to the given thunk.
        // Returns the stub rva.
        //
        std::optional<uint32_t> generate_stub( uint32_t rva, remote_ea_t thunk );

        // Attempts to convert the provided call to the VMP import stub to a direct import thunk call to the specified remote thunk ea.
        //
        bool convert_local_call( const import_call& call, remote_ea_t thunk );

        // Constructs a module_view from the given remote module base.
        //
        std::optional<module_view> view_from_base( remote_ea_t base ) const;

        // Retrieves the module base from the given remote ea.
        //
        std::optional<remote_ea_t> base_from_ea( remote_ea_t ea ) const;

        // Creates a vmpdump class from the given process id and target module name.
        // If module_name is empty "", the process module is used.
        // If the process cannot be opened for some reason or the module cannot be found, returns empty {}.
        //
        static std::unique_ptr<vmpdump> from_pid( uint32_t process_id, const std::string& module_name = "" );
        
        // Constructor.
        //
        vmpdump( uint32_t process_id, const std::map<remote_ea_t, std::pair<std::string, size_t>>& process_modules, std::unique_ptr<module_view> target_module_view, const std::string& module_full_path )
            : process_id( process_id ), process_modules( process_modules ), target_module_view( std::move( target_module_view ) ), module_full_path( module_full_path )
        {}
    };
}