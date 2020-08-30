#include "vmpdump.hpp"
#include <psapi.h>
#include <Shlwapi.h>
#include "disassembler.hpp"
#include <map>
#include <cstdint>
#include <vtil/compiler>
#include <vtil/common>
#include <vtil/symex>
#include <lifters/core>
#include <lifters/amd64>

namespace vmpdump
{
    struct import_stub_analysis
    {
        uintptr_t thunk_rva;
        uintptr_t dest_offset;
        int32_t stack_adjustment;
        bool padding;
        bool is_jmp;
    };

    // Attempts to generate structures from the provided call EA and instruction_stream of a VMP import stub.
    //
    std::optional<import_stub_analysis> analyze_import_stub( const instruction_stream& stream )
    {
        using namespace vtil;

        try
        {
            basic_block* lifted_block = stream.lift();

            auto iterator = std::prev( lifted_block->end() );

            if ( iterator->operands.size() != 1 || !iterator->operands[ 0 ].is_register() )
                return {};

            cached_tracer tracer;
            auto dest_expression = tracer.trace( { iterator, iterator->operands[ 0 ].reg() } );
            auto sp_expression = tracer.trace( { iterator, REG_SP } );
            auto retaddr_expression = tracer.trace( { iterator, { sp_expression, 64 } } );

            //logger::log<logger::CON_CYN>( "dest_expression: %s sp_expression: %s retaddr_expression: %s\r\n", dest_expression, sp_expression, retaddr_expression );

            uint64_t thunk_rva = 0;
            uint64_t dest_offset = 0;

            bool matched = false;
            {
                auto lhs = dest_expression->lhs;
                auto rhs = dest_expression->rhs;

                if ( lhs && rhs && lhs->is_variable() )
                {
                    auto lhs_var = lhs->uid.get<symbolic::variable>();

                    if ( auto rhs_const = rhs->get<uint64_t>() )
                    {
                        dest_offset = *rhs_const;
                        if ( lhs_var.is_memory() )
                        {
                            if ( auto pointer_val = lhs_var.mem().base.base->get<uint64_t>() )
                            {
                                thunk_rva = *pointer_val;
                                matched = true;
                            }
                        }
                    }
                }
            }

            if ( !matched )
                return {};

            symbolic::expression::reference retaddr_sp_exp;

            // Check if return address is padded.
            //
            bool pad = false;
            {
                auto lhs = retaddr_expression->lhs;
                auto rhs = retaddr_expression->rhs;

                if ( lhs && rhs && lhs->is_variable() && rhs->is_constant() )
                {
                    uint32_t constant = *rhs->get<uint32_t>();

                    if ( constant != 1 )
                        logger::log<logger::CON_PRP>( "** Warning: Unexpected value for padding: 0x%lx\r\n", constant );

                    pad = true;

                    // Set retaddr sp exp to [lhs].
                    //
                    retaddr_sp_exp = lhs->uid.get<symbolic::variable>().mem().base.base;
                }
                else
                    retaddr_sp_exp = retaddr_expression->uid.get<symbolic::variable>().mem().base.base;
            }

            //logger::log<logger::CON_CYN>( "retaddr_sp_exp: %s\r\n", retaddr_sp_exp );

            // Subtract initial SP from final SP to get the SP adjustment.
            //
            auto stack_adjustment_expr = ( sp_expression - symbolic::CTX( lifted_block->begin() )[ REG_SP ] ).simplify( true );
            //logger::log<logger::CON_CYN>( "stack_adjustment_expr: %s\r\n", stack_adjustment_expr );

            // Check if is jmp.
            //
            bool is_jmp = retaddr_sp_exp->equals( *sp_expression ) && *stack_adjustment_expr.get<int32_t>() >= 8;
            //logger::log<logger::CON_CYN>( "is_jmp: %d\r\n", is_jmp );

            if ( !stack_adjustment_expr.is_constant() )
                return {};

            // If is jump, expect stack adjustment of -0x8 to account for the initial call stub.
            //
            int32_t sp_adjustment = *stack_adjustment_expr.get<int32_t>() - ( is_jmp ? 8 : 0 );

            return
                import_stub_analysis{
                    thunk_rva,
                    dest_offset,
                    sp_adjustment,
                    pad,
                    is_jmp
            };
        }
        catch ( std::exception& ex )
        {
            logger::log( "%s", ex.what() );

            return {};
        }
    }

    // Scans the specified code range for any import calls and imports.
    // resolved_imports is a map of { import thunk rva, import structure }.
    //
    bool vmpdump::scan_for_imports( uint64_t rva, size_t code_size, std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t flags )
    {
        uint8_t* local_module_bytes = ( uint8_t* )target_module_view->local_module.data();

        size_t size = code_size;

        uint8_t* code_start = local_module_bytes + rva;

        uint64_t start_offset = rva;
        uint64_t offset = start_offset;

        // Retain the previously disassembled instruction for future use.
        //
        std::optional<instruction> previous_instruction = {};

        // While iterative disassembly is successful.
        //
        while ( true )
        {
            // Check if we're within bounds.
            //
            if ( offset >= start_offset + code_size )
                break;

            // In case disassembly failed (due to invalid instructions), try to continue by incrementing offset.
            //
            if ( !cs_disasm_iter( disassembler::get().get_handle(), ( const uint8_t** )&code_start, &size, &offset, disassembler::get().get_insn() ) )
            {
                offset++;
                code_start++;

                continue;
            }

            instruction ins = { disassembler::get().get_insn() };

            // In order to scan mutated code without failing, we are following 1 and 2 byte absolute jumps.
            //
            if ( ins.ins.id == X86_INS_JMP
                && ins.operand_type( 0 ) == X86_OP_IMM )
            {
                uint32_t jump_offset = ins.operand( 0 ).imm - ( ins.ins.address + ins.ins.size );

                if ( jump_offset == 1 || jump_offset == 2 )
                {
                    offset += jump_offset;
                    code_start += jump_offset;

                    previous_instruction = ins;

                    continue;
                }
            }

            // If the instruction is a relative ( E8 ) call.
            //
            if ( ins.ins.id == X86_INS_CALL && ins.operand_type( 0 ) == X86_OP_IMM && ins.ins.bytes[ 0 ] == 0xE8 )
            {
                uint64_t call_target_offset = ins.operand( 0 ).imm;
                uint8_t* call_target = local_module_bytes + call_target_offset;

                // VMP import stubs always begin with a NOP (0x90).
                // Ensure the current call matches this. Unfortunately we have to use the IsBadReadPtr API here as we
                // cannot be sure that we are dealing with valid code.
                //
                if ( !IsBadReadPtr( call_target, 1 ) && *call_target == 0x90 )
                {
                    // Disassemble at the call target.
                    //
                    instruction_stream stream = disassembler::get().disassemble( ( uint64_t )local_module_bytes, call_target_offset );

                    // Analyze the disassembled stream as a VMP import stub.
                    //
                    if ( std::optional<import_stub_analysis> stub_analysis = analyze_import_stub( stream ) )
                    {
                        //vtil::logger::log<vtil::logger::CON_GRN>( "0x%p\r\n", ins.ins.address );

                        // Compute the ea of the function, in the target process.
                        //
                        uintptr_t target_ea = *( uintptr_t* )( local_module_bytes + stub_analysis->thunk_rva ) + stub_analysis->dest_offset;

                        // If it doesn't already exist within the map, insert the import.
                        //
                        const resolved_import* referenced_import = &resolved_imports.insert( { stub_analysis->thunk_rva, { stub_analysis->thunk_rva, target_ea } } ).first->second;

                        // Record the call to the import.
                        //
                        import_calls.push_back( { ins.ins.address, referenced_import, stub_analysis->stack_adjustment, stub_analysis->padding, stub_analysis->is_jmp, previous_instruction } );

                        // If the call is a jump, and has no backwards (push) padding, it must be padded after the stub.
                        // Because jumps don't return, this information won't be provided to us by the analysis, so we have
                        // to skip the next byte to prevent potentially invalid disassembly.
                        //
                        if ( stub_analysis->is_jmp && stub_analysis->stack_adjustment == 0 )
                        {
                            offset++;
                            code_start++;
                        }
                    }
                }
            }

            previous_instruction = ins;
        }

        return true;
    }

    // Scans all executable sections of the image for any import calls and imports.
    //
    bool vmpdump::scan_for_imports( std::map<uint64_t, resolved_import>& resolved_imports, std::vector<import_call>& import_calls, uint32_t flags )
    {
        bool failed = false;

        auto nt = target_module_view->local_module.get_image()->get_nt_headers();

        // Enumerate image sections.
        //
        for ( int i = 0; i < nt->file_header.num_sections; i++ )
        {
            auto section = nt->get_section( i );

            if ( section->characteristics.mem_read && section->characteristics.mem_execute && section->characteristics.cnt_code )
                failed |= !scan_for_imports( section->virtual_address, section->virtual_size, resolved_imports, import_calls, flags );
        }

        return !failed;
    }

    // Attempts to generate a stub in a code cave which jmps to the given thunk.
    // Returns the stub rva.
    //
    std::optional<uint32_t> vmpdump::generate_stub( uint32_t rva, remote_ea_t thunk )
    {
        // Save all stubs so we don't re-create them on each call.
        //
        static std::map<remote_ea_t, uint32_t> stubs;

        // If the stub was already created, just return its rva.
        //
        auto it = stubs.find( thunk );
        if ( it != stubs.end() )
            return it->second;

        // We need 6 bytes for a thunk call.
        //
        const uint32_t req_len = 6;

        // Increase the section size.
        //
        auto section = target_module_view->local_module.get_image()->rva_to_section( rva );
        uint32_t stub_rva = section->virtual_address + section->virtual_size;
        section->virtual_size += req_len;

        // TODO: Handle if there is no more padding left in the section to overwrite.....
        //
        // ...

        // If no code-cave found, return empty {}.
        //
        if ( !stub_rva )
            return {};

        // Assemble a jump.
        //
        auto jump = vtil::amd64::assemble( vtil::format::str( "jmp [0x%p]", thunk ), target_module_view->module_base + stub_rva );

        // Sanity-check the size.
        //
        if ( jump.size() > 6 )
            return {};

        // Copy the assembled jump to the code-cave.
        //
        memcpy( target_module_view->local_module.data() + stub_rva, jump.data(), jump.size() );

        // Add the generated stub to the list for future use.
        //
        stubs.insert( { thunk, stub_rva } );

        return stub_rva;
    }

    // Attempts to convert the provided call to the VMP import stub to a direct import thunk call to the specified remote thunk ea.
    //
    bool vmpdump::convert_local_call( const import_call& call, remote_ea_t thunk )
    {
        uint8_t* local_module_bytes = ( uint8_t* )target_module_view->local_module.data();

        uint64_t fill_rva = 0;
        size_t fill_size = 0;

        // If the import stub call inline adjusts the stack, we must verify that the instruction
        // before the stub call is indeed a PUSH.
        //
        // In VMP3, the stack is only ever adjusted by a single 64-bit PUSH.
        //
        if ( call.stack_adjustment == 8 )
        {
            if ( call.prev_instruction && call.prev_instruction->ins.id == X86_INS_PUSH && call.prev_instruction->operand_type( 0 ) == X86_OP_REG )
            {
                // It is indeed a valid VMP-injected push.
                // We can NOP it later, and mark it as the starting point for our fill address.
                //
                fill_rva = call.prev_instruction->ins.address;
                fill_size += call.prev_instruction->ins.size;
            }
            else
            {
                vtil::logger::log<vtil::logger::CON_RED>( "!! Stack adjustment failed for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk );
                return false;
            }
        }

        uint8_t* call_ea = local_module_bytes + call.call_rva;

        // Disassemble instruction at the call rva.
        //
        auto instructions = vtil::amd64::disasm( call_ea, call.call_rva );

        // Ensure disassembly succeeded.
        //
        if ( instructions.empty() )
        {
            vtil::logger::log<vtil::logger::CON_RED>( "!! Disassembly failed for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk );
            return false;
        }

        // If it's a jump, we can increase fill size by 1, if we haven't already filled using a PUSH.
        // This is because thunk jumps must be 5 bytes, so VMP can insert a junk pad byte after its 4 byte stub.
        //
        if ( fill_size == 0 && call.is_jmp )
            fill_size++;

        // If there's no fill rva selected, set it as the beginning of the disassembled instructions.
        //
        if ( fill_rva == 0 )
            fill_rva = instructions[ 0 ].address;
        
        // Account for these instructions for the fill size.
        //
        for ( auto instruction : instructions )
            fill_size += instruction.bytes.size();

        // If padded, increase fill size by 1.
        //
        fill_size += call.padded ? 1 : 0;

        // Now we must inject a call to the newly-fixed thunk.
        //
        // We assemble this call as if we're in the target process address-space.
        // This is because we want to give the assembler the freedom to potentially make a non-relative call if it desires.
        //
        auto converted_call = vtil::amd64::assemble( vtil::format::str( "%s [0x%p]", call.is_jmp ? "jmp" : "call", thunk ), target_module_view->module_base + fill_rva );

        // Ensure assembly succeeded.
        //
        if ( converted_call.empty() )
        {
            vtil::logger::log<vtil::logger::CON_RED>( "!! Assembly failed for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", call.call_rva, thunk );
            return false;
        }

        // Ensure we have enough bytes to fill.
        //
        if ( converted_call.size() > fill_size )
        {
            // If we don't have enough bytes, we can try to dispatch the call via a stub.
            // Try to generate this stub in a codecave.
            //
            if ( std::optional<uint32_t> stub_rva = generate_stub( fill_rva, thunk ) )
            {
                // Successful, we found a suitable code-cave and generated a stub.
                // Now replace the call with a dispatched call (or jmp) to the stub.
                //
                converted_call = vtil::amd64::assemble( vtil::format::str( "%s 0x%p", call.is_jmp ? "jmp" : "call", target_module_view->module_base + *stub_rva ), target_module_view->module_base + fill_rva );
            }
        }

        // Ensure again we have enough bytes to fill.
        //
        if ( converted_call.size() > fill_size )
        {
            vtil::logger::log<vtil::logger::CON_RED>( "!! Insufficient bytes [have %d, need %d] for call @ RVA 0x%llx for thunk @ 0x%llx\r\n", fill_size, converted_call.size(), call.call_rva, thunk );
            return false;
        }

        // NOP the fill bytes and copy the converted call in.
        //
        memset( local_module_bytes + fill_rva, 0x90, fill_size );
        memcpy( local_module_bytes + fill_rva, converted_call.data(), converted_call.size() );

        return true;
    }

    // Searches for a module where the provided remote ea is within the module's address space, then returns a module_view of that module.
    //
    std::optional<module_view> vmpdump::view_from_base( remote_ea_t base ) const
    {
        // Find the module by base.
        //
        auto it = process_modules.find( base );
        
        // Return empty {} if not found.
        //
        if ( it == process_modules.end() )
            return {};

        // Construct module_view.
        //
        return { { process_id, it->second.first, base, it->second.second } };
    }

    // Retrieves the module base from the given remote ea.
    //
    std::optional<remote_ea_t> vmpdump::base_from_ea( remote_ea_t ea ) const
    {
        // Enumerate process modules.
        //
        for ( auto& [base, info] : process_modules )
        {
            // If within bounds, return module base.
            //
            if ( ea >= base && ea < base + info.second )
                return base;
        }

        // If none found, return empty {}.
        //
        return {};
    }

    // Creates a vmpdump class from the given process id and target module name.
    // If module_name is empty "", the process module is used.
    // If the process cannot be opened for some reason or the module cannot be found, returns empty {}.
    //
    std::unique_ptr<vmpdump> vmpdump::from_pid( uint32_t process_id, const std::string& module_name )
    {
        std::unique_ptr<vmpdump> result = {};

        HMODULE process_modules[ 1024 ] = {};

        // TODO: replace PROCESS_ALL_ACCESS with something more specific.
        //
        HANDLE process_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id );
        if ( process_handle == NULL )
            return {};

        // Retrieves the module base address and size, in that order, in a pair.
        //
        auto get_module_info = [&]( HMODULE target_module ) -> std::pair<uintptr_t, size_t>
        {
            MODULEINFO info = {};
            if ( !GetModuleInformation( process_handle, target_module, &info, sizeof( info ) ) )
                return { 0, 0 };

            return { ( uintptr_t )info.lpBaseOfDll, info.SizeOfImage };
        };

        // Do ... While( 0 ) "loop" for easy error wrapping.
        //
        do
        {
            // Try to get the process image file name.
            //
            char process_image_path[ MAX_PATH ] = {};
            DWORD process_image_path_size = sizeof( process_image_path );
            if ( !QueryFullProcessImageNameA( process_handle, 0, process_image_path, &process_image_path_size ) )
                break;

            const char* process_image_name = PathFindFileNameA( process_image_path );

            // Map of process modules, for later class construction.
            //
            std::map<remote_ea_t, std::pair<std::string, size_t>> process_modules_map;

            // Info of the target module.
            //
            std::string target_module_name;
            std::pair<uintptr_t, size_t> target_module_info = {};
            bool target_module_found = false;

            // Enumerate through the process modules list.
            //
            DWORD process_modules_size;
            if ( EnumProcessModules( process_handle, process_modules, sizeof( process_modules ), &process_modules_size ) )
            {
                // Loop through each module.
                //
                for ( int i = 0; i < ( process_modules_size / sizeof( HMODULE ) ); i++ )
                {
                    HMODULE curr_module = process_modules[ i ];

                    // Get the module base address and size.
                    //
                    std::pair<uintptr_t, size_t> curr_module_info = get_module_info( curr_module );

                    // Get the module name.
                    //
                    char module_base_name[ 64 ] = {};
                    if ( GetModuleBaseNameA( process_handle, curr_module, module_base_name, sizeof( module_base_name ) ) )
                    {
                        // Add the module to the map.
                        //
                        process_modules_map.insert( { curr_module_info.first, { module_base_name, curr_module_info.second } } );

                        // If we're looking for the process module, compare module name to image base name.
                        // Otherwise, compare the module name to the provided target module name in the argument.
                        //
                        if ( !target_module_found
                            && ( module_name.empty() && _stricmp( module_base_name, process_image_name ) == 0 )
                            || ( std::string( module_base_name ) == module_name ) )
                        {
                            target_module_info = curr_module_info;
                            target_module_name = module_base_name;
                            target_module_found = true;
                        }
                    }
                }
            }

            // Verify that we actually found the module.
            //
            if ( !target_module_found )
                break;

            // Construct the object.
            //
            result = std::make_unique<vmpdump>( process_id, process_modules_map, std::make_unique<module_view>( process_id, target_module_name, target_module_info.first, target_module_info.second ), std::string { process_image_path } );
            
        } while ( 0 );

        // Close handle and return the constructed object.
        //
        CloseHandle( process_handle );
        return result;
    }
}