
#include "vmpdump.hpp"
#include "tables.hpp"
#include <map>
#include <vtil/common>
#include "pe_constructor.hpp"
#include <fstream>
#include "winpe/image.hpp"
#include <sstream>
#include <filesystem>

#ifdef _MSC_VER
#pragma comment(linker, "/STACK:34359738368")
#endif

using namespace vtil::logger;

namespace vmpdump
{
    extern "C" int main( int argc, char* argv[] )
    {
#ifndef _DEBUG
        // Ensure required argument count.
        //
        if ( argc < 3 )
        {
            log<CON_RED>( "** Invalid arguments provided\r\n" );
            return 0;
        }

        std::vector<std::string> args;
        for ( int i = 0; i < argc; i++ )
            args.push_back( { argv[ i ] } );

        // Fetch target PID.
        //
        uint32_t pid = 0;
        ( std::stringstream( args[ 1 ] ) ) >> pid;

        // Try to parse hex.
        if ( pid == 0 )
            ( std::stringstream( args[ 1 ] ) ) >> std::hex >> pid;

        // Ensure PID validity.
        //
        if ( pid == 0 )
        {
            log<CON_RED>( "** Invalid PID 0x%lx provided\r\n", pid );
            return 0;
        }

        // Fetch target module name.
        //
        std::string target_module_name = args[ 2 ];

        std::optional<uint32_t> ep_rva = {};
        bool disable_relocation = false;

        // Fetch any other arguments.
        //
        for ( const std::string& arg : args )
        {
            // Should we overwrite the entry point with the user-provided EP?
            //
            if ( arg.find( "-ep=" ) == 0 )
            {
                uint32_t ep;
                ( std::stringstream( arg.substr( 4 ) ) ) >> std::hex >> ep;

                ep_rva = ep;
                continue;
            }

            // Should we mark in the dumped module that relocs have been stripped?
            //
            if ( arg.find( "-disable-reloc" ) )
            {
                disable_relocation = true;
                continue;
            }
        }
#else
        uint32_t pid = 0x5728;
        std::string target_module_name = "";
        std::optional<uint32_t> ep_rva = {};
        bool disable_relocation = true;
#endif

        std::unique_ptr<vmpdump> instance = vmpdump::from_pid( pid );

        if ( !instance )
        {
            log<CON_RED>( "** Failed to open process 0x%lx\r\n", pid );
            return 0;
        }

        log<CON_GRN>( "** Successfully opened process %s, PID 0x%lx\r\n", instance->target_module_view->module_name, instance->process_id );
        log<CON_GRN>( "** Selected module: %s\r\n", instance->module_full_path );

        std::map<uint64_t, resolved_import> resolved_imports = {};
        std::vector<import_call> import_calls = {};

        instance->scan_for_imports( resolved_imports, import_calls );

        log<CON_CYN>( "** Found %i calls to %i imports\r\n", import_calls.size(), resolved_imports.size() );

        // Define helper structures to organize retrieved data.
        //
        struct export_info
        {
            export_id_t id;
            uint32_t rva;
        };
        struct module_info
        {
            module_view view;
            std::vector<export_info> exports;
        };

        // Resolve exports for all found imports.
        //
        std::map<remote_ea_t, module_info> module_views;
        for ( auto& [thunk_rva, import] : resolved_imports )
        {
            // Resolve imported module base.
            //
            std::optional<remote_ea_t> import_module_base = instance->base_from_ea( import.target_ea );
            if ( !import_module_base )
            {
                log<CON_RED>( "\t** Failed to resolve import module of function 0x%p\r\n", import.target_ea );
                continue;
            }

            // If module view already exists, fetch it.
            //
            auto it = module_views.find( *import_module_base );
            if ( it == module_views.end() )
            {
                // Otherwise create the module view.
                //
                std::optional<module_view> import_module_view = instance->view_from_base( *import_module_base );
                if ( !import_module_view )
                {
                    log<CON_RED>( "\t** Failed to construct module view from base 0x%p\r\n", *import_module_base );
                    continue;
                }

                // And insert it into the map.
                //
                it = module_views.insert( { *import_module_base, { *import_module_view, {} } } ).first;
            }

            // Convert the import target remote ea to an export identifier for the target module.
            //
            std::optional<export_id_t> export_id = it->second.view.get_export( import.target_ea );
            if ( !export_id )
            {
                log<CON_RED>( "\t** Failed to resolve export for export 0x%p in module %s\r\n", import.target_ea, it->second.view.module_name );
                continue;
            }

            // Add the resolved export to the module's vector of exports.
            //
            it->second.exports.push_back( { *export_id, ( uint32_t )( import.target_ea - it->second.view.module_base ) } );

            // Notify the user that the export was resolved.
            //
            if ( !export_id->first.empty() )
            {
                log<CON_GRN>( "\t** Successfully resolved export ", export_id->first, it->second.view.module_name );
                log<CON_YLW>( "%s ", export_id->first );
                log<CON_GRN>( "in module " );
                log<CON_YLW>( "%s\r\n", it->second.view.module_name );
            }
            else
            {
                log<CON_GRN>( "\t** Successfully resolved export ", export_id->first, it->second.view.module_name );
                log<CON_YLW>( "0x%lx ", export_id->second );
                log<CON_GRN>( "in module " );
                log<CON_YLW>( "%s\r\n", it->second.view.module_name );
            }
        }

        // Build named imports.
        // These must be built seperately so that they are in the correct order.
        //
        std::vector<import_named_import> named_imports;
        for ( auto& [module_base, module_info] : module_views )
            for ( auto& [export_info, export_rva] : module_info.exports )
                if ( !export_info.first.empty() )
                    named_imports.push_back( { ( uint16_t )export_info.second, export_info.first } );

        win::image_t<true>* target_image = instance->target_module_view->local_module.get_image();
        win::nt_headers_x64_t* nt = target_image->get_nt_headers();

        // Serialize import names.
        //
        uint64_t import_section_begin_rva = pe_constructor::get_sections_end( instance->target_module_view->local_module );
        auto [named_imports_serialized, named_imports_rvas, named_imports_end] = pe_constructor::serialize_table( named_imports, import_section_begin_rva );

        // Build import thunks and import module names.
        //
        std::map<remote_ea_t, uint32_t> module_first_thunk_indices;
        std::vector<embedded_string> module_names;
        std::vector<image_thunk_data_x64> import_thunks;
        int name_index = 0;
        for ( auto& [module_base, module_info] : module_views )
        {
            module_first_thunk_indices.insert( { module_base, import_thunks.size() } );
            module_names.push_back( { module_info.view.module_name } );

            for ( auto& [export_info, export_rva] : module_info.exports ) 
            {
                auto& export_name = export_info.first;
                auto export_ordinal = export_info.second;

                // If not named import, import by ordinal.
                //
                if ( export_name.empty() )
                {
                    // Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                    //
                    image_thunk_data_x64 thunk = {};
                    thunk.is_ordinal = true;
                    thunk.ordinal = export_ordinal;

                    import_thunks.push_back( thunk );
                }
                // Otherwise, import by name RVA.
                //
                else
                {
                    uint32_t named_import_rva = named_imports_rvas[ name_index ];
                    name_index++;

                    import_thunks.push_back( image_thunk_data_x64{ .address = named_import_rva } );
                }
            }

            // Add an empty thunk to indicate module end.
            //
            import_thunks.push_back( {} );
        }

        // Serialize module names and import thunks.
        //
        auto [module_names_serialized, module_names_rvas, module_names_end] = pe_constructor::serialize_table( module_names, named_imports_end );

        // Unlike the import table, we aren't gonna create a new IAT; we are going to append the existing one instead.
        // This is because we want to make sure that the existing, non-obfuscated imports are still valid, and it's easier
        // to just append to the existing IAT rather than scanning for all existing imports and relocating them.
        //
        // TODO: Check if the IAT actually exists before using it.
        //
        uint32_t appended_import_thunks_rva = nt->optional_header.data_directories.iat_directory.rva + nt->optional_header.data_directories.iat_directory.size;
        auto [import_thunks_serialized, import_thunks_rvas, import_thunks_end] = pe_constructor::serialize_table( import_thunks, appended_import_thunks_rva );

        // Create map of {export remote ea, thunk rva} for easy future thunk lookup.
        //
        std::map<remote_ea_t, uint32_t> export_thunk_rvas;
        int thunk_index = 0;
        for ( auto& [module_base, module_info] : module_views )
        {
            for ( auto& [export_info, export_rva] : module_info.exports )
            {
                export_thunk_rvas.insert( { module_base + export_rva, import_thunks_rvas[ thunk_index ] } );
                thunk_index++;
            }
            thunk_index++;
        }

        // Now that we have built and serialized the new import thunks, we can fix the calls to said thunks.
        //
        log<CON_CYN>( "** Converting %i calls\r\n", import_calls.size(), resolved_imports.size() );
        for ( auto& import_call : import_calls )
        {
            if ( instance->convert_local_call( import_call, instance->target_module_view->module_base + export_thunk_rvas[ import_call.import->target_ea ] ) )
                log<CON_GRN>( "\t** Successfully converted call @ RVA 0x%lx to thunk @ RVA 0x%lx\r\n", import_call.call_rva, export_thunk_rvas[ import_call.import->target_ea ] );
            else
                log<CON_RED>( "\t** Failed to convert call @ RVA 0x%lx\r\n", import_call.call_rva );
        }

        // Parse & transfer existing import directories.
        // As we are creating a new import table, we must preserve the current one by copying it.
        //
        std::vector<import_directory> import_directories;
        auto existing_imports_base = instance->target_module_view->local_module.raw_bytes.data() + nt->optional_header.data_directories.import_directory.rva;
        size_t import_table_offset = 0;
        while ( true )
        {
            // Verify we have enough space left for another iteration.
            //
            if ( import_table_offset + sizeof( win::import_directory_t ) >= nt->optional_header.data_directories.import_directory.size )
                break;

            win::import_directory_t* import_dir = ( win::import_directory_t* )( existing_imports_base + import_table_offset );

            import_directories.push_back(
                {
                    .rva_original_first_thunk = import_dir->rva_original_first_thunk,
                    .timedate_stamp = import_dir->timedate_stamp,
                    .forwarder_chain = import_dir->forwarder_chain,
                    .rva_name = import_dir->rva_name,
                    .rva_first_thunk = import_dir->rva_first_thunk
                } );

            // Increment the import table offset by the table size.
            //
            import_table_offset += sizeof( win::import_directory_t );
        }

        // Build import directories.
        //
        int i = 0;
        for ( auto [module_base, first_thunk_index] : module_first_thunk_indices )
        {
            import_directories.push_back(
                {
                    .rva_original_first_thunk = import_thunks_rvas[ first_thunk_index ],
                    .timedate_stamp = 0,
                    .forwarder_chain = 0,
                    .rva_name = module_names_rvas[ i ],
                    .rva_first_thunk = import_thunks_rvas[ first_thunk_index ]
                } );
            i++;
        }

        // Serialize import directories.
        //
        auto [import_directories_serialized, import_directories_rvas, import_directories_end] = pe_constructor::serialize_table( import_directories, module_names_end );

        // Concat each serialized buffer to build the new import table section.
        //
        std::vector<uint8_t> import_section;
        import_section.insert( import_section.end(), named_imports_serialized.begin(), named_imports_serialized.end() );
        import_section.insert( import_section.end(), module_names_serialized.begin(), module_names_serialized.end() );
        import_section.insert( import_section.end(), import_directories_serialized.begin(), import_directories_serialized.end() );

        // Convert the virtual pe image to a raw pe image.
        //
        pe_image raw_module = pe_constructor::virtual_to_raw_image( instance->target_module_view->local_module );

        // Add the new section to the raw module.
        //
        pe_constructor::add_section( raw_module, import_section, import_section_begin_rva, ".vmpdmp", { 0x40000040 } );

        // Set new import data directory.
        //
        auto raw_nt = raw_module.get_image()->get_nt_headers();
        raw_nt->optional_header.data_directories.import_directory.rva = module_names_end;
        raw_nt->optional_header.data_directories.import_directory.size = import_directories_end - module_names_end;

        // Add our new import thunks to the pre-existing IAT.
        // TODO: verify we have enough space left in the section!
        //
        memcpy( raw_module.get_image()->rva_to_ptr( appended_import_thunks_rva ), import_thunks_serialized.data(), import_thunks_serialized.size() );
        raw_nt->optional_header.data_directories.iat_directory.size += import_thunks_serialized.size();

        // Update EP if provided.
        //
        if ( ep_rva )
            raw_nt->optional_header.entry_point = *ep_rva;

        // Disable relocation if requested.
        //
        if ( disable_relocation )
            raw_nt->file_header.characteristics.relocs_stripped = true;

        log<CON_GRN>( "** New ImageBase: 0x%llx, SizeOfImage: 0x%lx\r\n", raw_nt->optional_header.image_base, raw_nt->optional_header.size_image );

        // Save module.
        //
        std::filesystem::path module_path = { instance->module_full_path };
        module_path.replace_extension( "VMPDump" + module_path.extension().string() );
        std::ofstream outfile( module_path.string(), std::ios::out | std::ios::binary );
        outfile.write( ( const char* )raw_module.raw_bytes.data(), raw_module.raw_bytes.size() );

        log<CON_GRN>( "** File written to: %s\r\n", module_path.string() );

        return 0;
    }
}