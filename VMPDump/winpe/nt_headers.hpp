#pragma once
#include "common.hpp"

#pragma pack(push, WIN_STRUCT_PACKING)
namespace win
{
	// Magic constants
	//
	static constexpr uint16_t DOS_HDR_MAGIC =			0x5A4D;			// "MZ"
	static constexpr uint32_t NT_HDR_MAGIC =			0x00004550;		// "PE\x0\x0"
	static constexpr uint16_t OPT_HDR32_MAGIC =			0x010B;
	static constexpr uint16_t OPT_HDR64_MAGIC =			0x020B;
	static constexpr bool IS_DEF_AMD64 =				sizeof( void* ) == 8;
	
	static constexpr uint32_t NUM_DATA_DIRECTORIES =	16;
	static constexpr uint32_t LEN_SECTION_NAME =		8;

	// File target machine
	//
	enum class machine_id : uint16_t
	{
		unknown =										0x0000,
		target_host =									0x0001,			// Useful for indicating we want to interact with the host and not a WoW guest.
		i386 =											0x014C,			// Intel 386.
		r3000 =											0x0162,			// MIPS little-endian, 0x160 big-endian
		r4000 =											0x0166,			// MIPS little-endian
		r10000 =										0x0168,			// MIPS little-endian
		wcemipsv2 =										0x0169,			// MIPS little-endian WCE v2
		alpha =											0x0184,			// Alpha_AXP
		sh3 =											0x01A2,			// SH3 little-endian
		sh3dsp =										0x01A3,
		sh3e =											0x01A4,			// SH3E little-endian
		sh4 =											0x01A6,			// SH4 little-endian
		sh5 =											0x01A8,			// SH5
		arm =											0x01C0,			// ARM Little-Endian
		thumb =											0x01C2,			// ARM Thumb/Thumb-2 Little-Endian
		armnt =											0x01C4,			// ARM Thumb-2 Little-Endian
		am33 =											0x01D3,
		powerpc =										0x01F0,			// IBM PowerPC Little-Endian
		powerpcfp =										0x01F1,
		ia64 =											0x0200,			// Intel 64
		mips16 =										0x0266,			// MIPS
		alpha64 =										0x0284,			// ALPHA64
		mipsfpu =										0x0366,			// MIPS
		mipsfpu16 =										0x0466,			// MIPS
		axp64 =											0x0284,
		tricore =										0x0520,			// Infineon
		cef =											0x0CEF,
		ebc =											0x0EBC,			// EFI Byte Code
		amd64 =											0x8664,			// AMD64 (K8)
		m32r =											0x9041,			// M32R little-endian
		arm64 =											0xAA64,			// ARM64 Little-Endian
		cee =											0xC0EE,
	};

	// Subsystems
	//
	enum class subsystem_id : uint16_t
	{
		unknown =										0x0000,			// Unknown subsystem.
		native =										0x0001,			// Image doesn't require a subsystem.
		windows_gui =									0x0002,			// Image runs in the Windows GUI subsystem.
		windows_cui =									0x0003,			// Image runs in the Windows character subsystem
		os2_cui =										0x0005,			// image runs in the OS/2 character subsystem.
		posix_cui =										0x0007,			// image runs in the Posix character subsystem.
		native_windows =								0x0008,			// image is a native Win9x driver.
		windows_ce_gui =								0x0009,			// Image runs in the Windows CE subsystem.
		efi_application =								0x000A,			//
		efi_boot_service_driver =						0x000B,			//
		efi_runtime_driver =							0x000C,			//
		efi_rom =										0x000D,
		xbox =											0x000E,
		windows_boot_application =						0x0010,
		xbox_code_catalog =								0x0011,
	};

	// Directory indices
	//
	enum directory_id
	{
		directory_entry_export =						0,				// Export Directory
		directory_entry_import =						1,				// Import Directory
		directory_entry_resource =						2,				// Resource Directory
		directory_entry_exception =						3,				// Exception Directory
		directory_entry_security =						4,				// Security Directory
		directory_entry_basereloc =						5,				// Base Relocation Table
		directory_entry_debug =							6,				// Debug Directory
		directory_entry_copyright =						7,				// (X86 usage)
		directory_entry_architecture =					7,				// Architecture Specific Data
		directory_entry_globalptr =						8,				// RVA of GP
		directory_entry_tls =							9,				// TLS Directory
		directory_entry_load_config =					10,				// Load Configuration Directory
		directory_entry_bound_import =					11,				// Bound Import Directory in headers
		directory_entry_iat =							12,				// Import Address Table
		directory_entry_delay_import =					13,				// Delay Load Import Descriptors
		directory_entry_com_descriptor =				14,				// COM Runtime descriptor
		directory_reserved0 =							15,				// -
	};

	// File characteristics
	//
	union file_characteristics_t
	{
		uint16_t flags;
		struct
		{
			uint16_t relocs_stripped					: 1;			// Relocation info stripped from file.
			uint16_t executable							: 1;			// File is executable  (i.e. no unresolved external references).
			uint16_t lines_stripped						: 1;			// Line nunbers stripped from file.
			uint16_t local_symbols_stripped				: 1;			// Local symbols stripped from file.
			uint16_t aggressive_ws_trim					: 1;			// Aggressively trim working set
			uint16_t large_address_aware				: 1;			// App can handle >2gb addresses
			uint16_t _pad0								: 1;
			uint16_t bytes_reversed_lo					: 1;			// Bytes of machine word are reversed.
			uint16_t machine_32							: 1;			// 32 bit word machine.
			uint16_t debug_stripped						: 1;			// Debugging info stripped from file in .DBG file
			uint16_t runnable_from_swap					: 1;			// If Image is on removable media, copy and run from the swap file.
			uint16_t net_run_from_swap					: 1;			// If Image is on Net, copy and run from the swap file.
			uint16_t system_file						: 1;			// System File.
			uint16_t dll_file							: 1;			// File is a DLL.
			uint16_t up_system_only						: 1;			// File should only be run on a UP machine
			uint16_t bytes_reversed_hi					: 1;			// Bytes of machine word are reversed.
		};
	};
	
	// DLL characteristics
	//
	union dll_characteristics_t
	{
		uint16_t flags;
		struct
		{
			uint16_t _pad0								: 5;
			uint16_t high_entropy_va					: 1;			// Image can handle a high entropy 64-bit virtual address space.
			uint16_t dynamic_base						: 1;			// DLL can move.
			uint16_t force_integrity					: 1;			// Code Integrity Image
			uint16_t nx_compat							: 1;			// Image is NX compatible
			uint16_t no_isolation						: 1;			// Image understands isolation and doesn't want it
			uint16_t no_seh								: 1;			// Image does not use SEH.  No SE handler may reside in this image
			uint16_t no_bind							: 1;			// Do not bind this image.
			uint16_t appcontainer						: 1;			// Image should execute in an AppContainer
			uint16_t wdm_driver							: 1;			// Driver uses WDM model
			uint16_t guard_cf							: 1;			// Image supports Control Flow Guard.
			uint16_t terminal_server_aware				: 1;
		};
	};

	// Section characteristics
	//
	union section_characteristics_t
	{
		uint32_t flags;
		struct
		{
			uint32_t _pad0								: 5;
			uint32_t cnt_code							: 1;			// Section contains code.
			uint32_t cnt_init_data						: 1;			// Section contains initialized data.
			uint32_t cnt_uninit_data					: 1;			// Section contains uninitialized data.
			uint32_t _pad1								: 1;
			uint32_t lnk_info							: 1;			// Section contains comments or some other type of information.
			uint32_t _pad2								: 1;
			uint32_t lnk_remove							: 1;			// Section contents will not become part of image.
			uint32_t lnk_comdat							: 1;			// Section contents comdat.
			uint32_t _pad3								: 1;
			uint32_t no_defer_spec_exc					: 1;			// Reset speculative exceptions handling bits in the TLB entries for this section.
			uint32_t mem_far							: 1;
			uint32_t _pad4								: 1;
			uint32_t mem_purgeable						: 1;
			uint32_t mem_locked							: 1;
			uint32_t mem_preload						: 1;
			uint32_t alignment							: 4;			// Alignment calculated as: n ? 1 << ( n - 1 ) : 16 
			uint32_t lnk_nreloc_ovfl					: 1;			// Section contains extended relocations.
			uint32_t mem_discardable					: 1;			// Section can be discarded.
			uint32_t mem_not_cached						: 1;			// Section is not cachable.
			uint32_t mem_not_paged						: 1;			// Section is not pageable.
			uint32_t mem_shared							: 1;			// Section is shareable.
			uint32_t mem_execute						: 1;			// Section is executable.
			uint32_t mem_read							: 1;			// Section is readable.
			uint32_t mem_write							: 1;			// Section is writeable.
		};
		
		inline uint32_t get_alignment() { return alignment ? 1 << ( alignment - 1 ) : 0x10; }
		inline void set_alignment( uint32_t a ) { alignment = a == 0x10 ? 0x0 : __builtin_ctz( a ) + 1; }
	};

	// NT versioning
	//
	union version_t
	{
		uint16_t					identifier;
		struct
		{
			uint8_t					major;
			uint8_t					minor;
		};
	};

	union ex_version_t
	{
		uint32_t					identifier;
		struct
		{
			uint16_t				major;
			uint16_t				minor;
		};
	};

	// File header
	//
	struct file_header_t
	{
		machine_id					machine;
		uint16_t					num_sections;
		uint32_t					timedate_stamp;
		uint32_t					ptr_symbols;
		uint32_t					num_symbols;
		uint16_t					size_optional_header;
		file_characteristics_t		characteristics;
	};

	// Data directories
	//
	struct data_directory_t
	{
		uint32_t					rva;
		uint32_t					size;

		inline bool present() { return size; }
	};

	struct data_directories_x86_t
	{
		union
		{
			struct
			{
				data_directory_t	export_directory;
				data_directory_t	import_directory;
				data_directory_t	resource_directory;
				data_directory_t	exception_directory;
				data_directory_t	security_directory;
				data_directory_t	basereloc_directory;
				data_directory_t	debug_directory;
				data_directory_t	copyright_directory;
				data_directory_t	globalptr_directory;
				data_directory_t	tls_directory;
				data_directory_t	load_config_directory;
				data_directory_t	bound_import_directory;
				data_directory_t	iat_directory;
				data_directory_t	delay_import_directory;
				data_directory_t	com_descriptor_directory;
				data_directory_t	_reserved0;
			};
			data_directory_t		entries[ NUM_DATA_DIRECTORIES ];
		};
	};

	struct data_directories_x64_t
	{
		union
		{
			struct
			{
				data_directory_t	export_directory;
				data_directory_t	import_directory;
				data_directory_t	resource_directory;
				data_directory_t	exception_directory;
				data_directory_t	security_directory;
				data_directory_t	basereloc_directory;
				data_directory_t	debug_directory;
				data_directory_t	architecture_directory;
				data_directory_t	globalptr_directory;
				data_directory_t	tls_directory;
				data_directory_t	load_config_directory;
				data_directory_t	bound_import_directory;
				data_directory_t	iat_directory;
				data_directory_t	delay_import_directory;
				data_directory_t	com_descriptor_directory;
				data_directory_t	_reserved0;
			};
			data_directory_t		entries[ NUM_DATA_DIRECTORIES ];
		};
	};

	template<bool x64 = IS_DEF_AMD64, 
		typename base_type = typename std::conditional<x64, data_directories_x64_t, data_directories_x86_t>::type>
	struct data_directories_t : base_type {};
	static_assert( sizeof( data_directories_t<false> ) == sizeof( data_directories_x86_t ) &&
				   sizeof( data_directories_t<true> ) == sizeof( data_directories_x64_t ),
				   "Empty structure influenced structure size." );

	// Optional header
	//
	struct optional_header_x64_t
	{
		// Standard fields.
		uint16_t					magic;
		version_t					linker_version;

		uint32_t					size_code;
		uint32_t					size_init_data;
		uint32_t					size_uninit_data;
		
		uint32_t					entry_point;
		uint32_t					base_of_code;

		// NT additional fields.
		uint64_t					image_base;
		uint32_t					section_alignment;
		uint32_t					file_alignment;
		
		ex_version_t				os_version;
		ex_version_t				img_version;
		ex_version_t				subsystem_version;
		uint32_t					win32_version_value;
		
		uint32_t					size_image;
		uint32_t					size_headers;
		
		uint32_t					checksum;
		subsystem_id				subsystem;
		dll_characteristics_t		characteristics;
		
		uint64_t					size_stack_reserve;
		uint64_t					size_stack_commit;
		uint64_t					size_heap_reserve;
		uint64_t					size_heap_commit;
		
		uint32_t					ldr_flags;

		uint32_t					num_data_directories;
		data_directories_x64_t		data_directories;
	};

	struct optional_header_x86_t
	{
		// Standard fields.
		uint16_t					magic;
		version_t					linker_version;

		uint32_t					size_code;
		uint32_t					size_init_data;
		uint32_t					size_uninit_data;

		uint32_t					entry_point;
		uint32_t					base_of_code;
		uint32_t					base_of_data;

		// NT additional fields.
		uint32_t					image_base;
		uint32_t					section_alignment;
		uint32_t					file_alignment;

		ex_version_t				os_version;
		ex_version_t				img_version;
		ex_version_t				subsystem_version;
		uint32_t					win32_version_value;

		uint32_t					size_image;
		uint32_t					size_headers;

		uint32_t					checksum;
		subsystem_id				subsystem;
		dll_characteristics_t		characteristics;

		uint32_t					size_stack_reserve;
		uint32_t					size_stack_commit;
		uint32_t					size_heap_reserve;
		uint32_t					size_heap_commit;

		uint32_t					ldr_flags;

		uint32_t					num_data_directories;
		data_directories_x86_t		data_directories;

		inline bool has_directory( data_directory_t* dir ) { return &data_directories.entries[ num_data_directories ] < dir && dir->present(); }
		inline bool has_directory( directory_id id ) { return has_directory( &data_directories.entries[ id ] ); }
	};

	template<bool x64 = IS_DEF_AMD64, 
		typename base_type = typename std::conditional<x64, optional_header_x64_t, optional_header_x86_t>::type>
	struct optional_header_t : base_type {};
	static_assert( sizeof( optional_header_t<false> ) == sizeof( optional_header_x86_t ) &&
				   sizeof( optional_header_t<true> ) == sizeof( optional_header_x64_t ),
				   "Empty structure influenced structure size." );

	// Section header
	//
	struct section_header_t
	{
		char						name[ LEN_SECTION_NAME ];
		
		union
		{
			uint32_t				physical_address;
			uint32_t				virtual_size;
		};
		uint32_t					virtual_address;
		
		uint32_t					size_raw_data;
		uint32_t					ptr_raw_data;
		
		uint32_t					ptr_relocs;
		uint32_t					ptr_line_numbers;
		uint16_t					num_relocs;
		uint16_t					num_line_numbers;
		
		section_characteristics_t	characteristics;
	};

	// NT headers
	//
	template<bool x64 = IS_DEF_AMD64>
	struct nt_headers_t
	{
		uint32_t					signature;
		file_header_t				file_header;
		optional_header_t<x64>		optional_header;

		inline section_header_t* get_sections() { return ( section_header_t* ) ( ( uint8_t* ) &optional_header + file_header.size_optional_header ); }
		inline section_header_t* get_section( int n ) { return get_sections() + n; }
	};
	using nt_headers_x64_t = nt_headers_t<true>;
	using nt_headers_x86_t = nt_headers_t<false>;

	// DOS header
	//
	struct dos_header_t
	{
		uint16_t					e_magic;
		uint16_t					e_cblp;
		uint16_t					e_cp;
		uint16_t					e_crlc;
		uint16_t					e_cparhdr;
		uint16_t					e_minalloc;
		uint16_t					e_maxalloc;
		uint16_t					e_ss;
		uint16_t					e_sp;
		uint16_t					e_csum;
		uint16_t					e_ip;
		uint16_t					e_cs;
		uint16_t					e_lfarlc;
		uint16_t					e_ovno;
		uint16_t					e_res[ 4 ];
		uint16_t					e_oemid;
		uint16_t					e_oeminfo;
		uint16_t					e_res2[ 10 ];
		uint32_t					e_lfanew;

		template<bool x64 = IS_DEF_AMD64> inline auto get_nt_headers() { return ( nt_headers_t<x64>* ) ( ( uint8_t* ) this + e_lfanew ); }
	};
};
#pragma pack(pop)