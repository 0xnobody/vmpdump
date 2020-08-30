#include "module_view.hpp"
#include <windows.h>

namespace vmpdump
{
    // Commits any local module changes back to the target process.
    //
    bool module_view::commit() const
    {
        bool result = false;

        // Try to open the process.
        //
        HANDLE process_handle = OpenProcess( PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, process_id );
        if ( !process_handle )
            return false;

        // Get RWX permissions.
        //
        DWORD new_protect = PAGE_EXECUTE_READWRITE;
        DWORD old_protect;
        if ( !VirtualProtectEx( process_handle, ( LPVOID )module_base, module_size, new_protect, &old_protect ) )
            goto cleanup;

        // Write the memory.
        //
        SIZE_T num_written;
        if ( WriteProcessMemory( process_handle, ( LPVOID )module_base, local_module.cdata(), local_module.size(), &num_written ) && num_written == module_size )
            result = true;

        // Restore old memory permissions.
        //
        if ( !VirtualProtectEx( process_handle, ( LPVOID )module_base, module_size, old_protect, &new_protect ) )
            result = false;

        // On function exit, close the handle.
        //
    cleanup:
        CloseHandle( process_handle );
        return result;
    }

    // Fetches any remote module changes back to the local module buffer.
    //
    bool module_view::fetch()
    {
        bool result = false;

        // Try to open the process.
        //
        HANDLE process_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id );
        if ( !process_handle )
            return false;

        // Resize the local module in case it's not allocated yet.
        //
        local_module.raw_bytes.resize( module_size );

        // Read the memory.
        //
        SIZE_T num_written;
        if ( ReadProcessMemory( process_handle, ( LPVOID )module_base, local_module.data(), local_module.size(), &num_written ) && num_written == local_module.size() )
            result = true;

        // On function exit, close the handle.
        //
    cleanup:
        CloseHandle( process_handle );
        return result;
    }

    // Returns the export name (if available) and ordinal.
    //
    std::optional<export_id_t> module_view::get_export( remote_ea_t ea )
    {
        using namespace win;

        uint64_t rva = ea - module_base;

        // Check if ea is in module bounds.
        //
        if ( !within_bounds( ea ) )
            return {};

        auto image = local_module.get_image();

        auto export_dir_header = image->get_directory( directory_id::directory_entry_export );
        if ( !export_dir_header->present() )
            return {};

        auto export_dir = ( export_directory_t* )( local_module.data() + export_dir_header->rva );

        // Resolve effective addresses of each export table.
        //
        uint32_t* eat = ( uint32_t* )( local_module.data() + export_dir->rva_functions );
        uint32_t* names = ( uint32_t* )( local_module.data() + export_dir->rva_names );
        uint16_t* name_ordinals = ( uint16_t* )( local_module.data() + export_dir->rva_name_ordinals );

        uint32_t function_ordinal = -1;

        // Resolve function ordinal.
        //
        for ( uint32_t i = 0; i < export_dir->num_functions; i++ )
            if ( eat[ i ] == rva )
                function_ordinal = i;

        // Verify function was found.
        //
        if ( function_ordinal == -1 )
            return {};
        
        uint32_t name_ordinal = -1;

        // Resolve name ordinal.
        //
        for ( uint32_t i = 0; i < export_dir->num_names; i++ )
            if ( name_ordinals[ i ] == function_ordinal )
                name_ordinal = i;

        uint32_t ordinal = export_dir->base + function_ordinal;

        // If no name ordinal found, return function ordinal.
        //
        if ( name_ordinal == -1 )
            return { { { "" }, ordinal } };

        // Return function name.
        //
        return { { std::string( ( const char* )( local_module.data() + names[ name_ordinal ] ) ), ordinal } };
    }
}