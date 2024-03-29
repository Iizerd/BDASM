#pragma once

// Did you know that pex looks like xed if it was flipped upside down?
// PEX = PE(X), the X being 32 or 64 bit executables.
// This is how BDASM interfaces with the PE and its structures.
// 
// Can map a PE into memory as if it was a loaded image, modify it,
// then unmap back to raw data to be written to disk.
// Notable code is append_section and map/unmap_file
//

#include <Windows.h>
#include <string_view>
#include <string>
#include <vector>
#include <variant>
#include <filesystem>
#include <functional>
#include <fstream>
#include <map>
#include <set>
#include <type_traits>
#include <mutex>

#include "traits.h"
#include "addr_width.h"
#include "symbol.h"
#include "align.h"

namespace pex
{

	typedef IMAGE_DOS_HEADER image_dos_header_t;
	typedef IMAGE_FILE_HEADER image_file_header_t;
	typedef IMAGE_NT_HEADERS32 image_nt_headers32_t;
	typedef IMAGE_NT_HEADERS64 image_nt_headers64_t;
	typedef IMAGE_SECTION_HEADER image_section_header_t;
	typedef IMAGE_IMPORT_DESCRIPTOR image_import_descriptor_t;
	typedef IMAGE_BOUND_IMPORT_DESCRIPTOR image_bound_import_descriptor_t;
	typedef IMAGE_BASE_RELOCATION image_base_relocation_t;
	typedef IMAGE_EXPORT_DIRECTORY image_export_dir_t;
	typedef IMAGE_DATA_DIRECTORY image_data_dir_t;
	typedef IMAGE_RESOURCE_DIRECTORY_ENTRY image_resource_dir_entry_t;
	typedef IMAGE_RESOURCE_DIRECTORY image_resource_dir_t;
	typedef IMAGE_TLS_DIRECTORY32 image_tls_dir32_t;
	typedef IMAGE_TLS_DIRECTORY64 image_tls_dir64_t;
	typedef IMAGE_THUNK_DATA32 image_thunk_data32_t;
	typedef IMAGE_THUNK_DATA64 image_thunk_data64_t;
	typedef IMAGE_OPTIONAL_HEADER32 image_optional_header32_t;
	typedef IMAGE_OPTIONAL_HEADER64 image_optional_header64_t;
	typedef IMAGE_IMPORT_BY_NAME image_import_by_name_t;
	typedef IMAGE_RUNTIME_FUNCTION_ENTRY image_runtime_function_entry_t;


	typedef std::vector<uint8_t> byte_vector;

#define _DEFINE_GETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) ndiscard __forceinline decltype(_Sd::_ItemName) get_##_RealName##() const
#define _DEFINE_SETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) __forceinline void set_##_RealName##(decltype(_Sd::_ItemName) value)

#define _DEFINE_GETTER(_Sd, _Sn, _ItemName, _RealName) \
	_DEFINE_GETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) { return _Sn##_ItemName; }
#define _DEFINE_SETTER(_Sd, _Sn, _ItemName, _RealName) \
	_DEFINE_SETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) { _Sn##_ItemName = value; }

	// Is this really an iterators?
	// I think not, come up with a better name.
	//
	template <typename Class_type, typename It_type>
	class base_it_t
	{
		base_it_t()
			: m_pdata(nullptr) {}

	protected:
		Class_type* m_pdata;

	public:

		using My_type = Class_type;

		base_it_t(Class_type* ptr)
			: m_pdata(ptr) {}
		base_it_t(base_it_t const& to_copy)
			: m_pdata(to_copy.m_pdata) {}
		void append_to_vec(byte_vector& vec)
		{
			vec.insert(vec.end(), (uint8_t*)m_pdata, (uint8_t*)m_pdata + sizeof Class_type);
		}
		void copy_to_data(void* raw_data)
		{
			std::memcpy(raw_data, m_pdata, sizeof Class_type);
		}
		void copy_from_data(void* raw_data)
		{
			std::memcpy(m_pdata, raw_data, sizeof Class_type);
		}
		Class_type* get() const
		{
			return m_pdata;
		}
		void set(void* ptr)
		{
			m_pdata = reinterpret_cast<Class_type*>(ptr);
		}
		uint8_t* get_byte_ptr()
		{
			return reinterpret_cast<uint8_t*>(m_pdata);
		}
		It_type& operator++()
		{
			++m_pdata;
			return *static_cast<It_type*>(this);
		}
		ndiscard It_type operator++(int)
		{
			return It_type(m_pdata++);
		}
		It_type operator--()
		{
			--m_pdata;
			return *static_cast<It_type*>(this);
		}
		ndiscard It_type operator--(int)
		{
			return It_type(m_pdata--);
		}
		It_type operator[](uint32_t index)
		{
			return It_type(m_pdata + index);
		}

	};

#define _DATA_DIR_ITEM_LIST(_Sd, _Sn, _M)          \
	_M(_Sd, _Sn, VirtualAddress, virtual_address); \
	_M(_Sd, _Sn, Size, size);
	class data_dir_it_t : public base_it_t<image_data_dir_t, data_dir_it_t>
	{
		data_dir_it_t()
			: base_it_t(nullptr) {}

	public:
		data_dir_it_t(image_data_dir_t* raw_data)
			: base_it_t(raw_data) {}
		_DATA_DIR_ITEM_LIST(image_data_dir_t, this->m_pdata->, _DEFINE_GETTER)
			_DATA_DIR_ITEM_LIST(image_data_dir_t, this->m_pdata->, _DEFINE_SETTER)
	};


#define _DOS_HEADER_ITEM_LIST(_Sd, _Sn, _M) \
	_M(_Sd, _Sn, e_magic, magic);           \
	_M(_Sd, _Sn, e_cblp, cblp);             \
	_M(_Sd, _Sn, e_cp, cp);                 \
	_M(_Sd, _Sn, e_crlc, crlc);             \
	_M(_Sd, _Sn, e_cparhdr, cparhdr);       \
	_M(_Sd, _Sn, e_minalloc, minalloc);     \
	_M(_Sd, _Sn, e_maxalloc, maxalloc);     \
	_M(_Sd, _Sn, e_ss, ss);                 \
	_M(_Sd, _Sn, e_sp, sp);                 \
	_M(_Sd, _Sn, e_csum, csum);             \
	_M(_Sd, _Sn, e_ip, ip);                 \
	_M(_Sd, _Sn, e_cs, cs);                 \
	_M(_Sd, _Sn, e_lfarlc, lfarlc);         \
	_M(_Sd, _Sn, e_ovno, ovno);             \
	_M(_Sd, _Sn, e_oemid, oemid);           \
	_M(_Sd, _Sn, e_oeminfo, oeminfo);       \
	_M(_Sd, _Sn, e_lfanew, lfanew);
	class dos_header_it_t : public base_it_t<image_dos_header_t, dos_header_it_t>
	{
		dos_header_it_t()
			: base_it_t(nullptr) {}

	public:
		dos_header_it_t(image_dos_header_t* raw_data)
			: base_it_t(raw_data) {}
		uint16_t* res_at_idx(uint32_t idx)
		{
			if (idx < 4)
				return &m_pdata->e_res[idx];
			return nullptr;
		}
		uint16_t* res2_at_idx(uint32_t idx)
		{
			if (idx < 10)
				return &m_pdata->e_res2[idx];
			return nullptr;
		}

		_DOS_HEADER_ITEM_LIST(image_dos_header_t, this->m_pdata->, _DEFINE_GETTER)
			_DOS_HEADER_ITEM_LIST(image_dos_header_t, this->m_pdata->, _DEFINE_SETTER)
	};


#define _FILE_HEADER_ITEM_LIST(_Sd, _Sn, _M)                    \
	_M(_Sd, _Sn, Machine, machine)                              \
	_M(_Sd, _Sn, NumberOfSections, number_of_sections)          \
	_M(_Sd, _Sn, TimeDateStamp, date_time_stamp)                \
	_M(_Sd, _Sn, PointerToSymbolTable, pointer_to_symbol_data)  \
	_M(_Sd, _Sn, NumberOfSymbols, number_of_symbols)            \
	_M(_Sd, _Sn, SizeOfOptionalHeader, size_of_optional_header) \
	_M(_Sd, _Sn, Characteristics, characteristics)
	class file_header_it_t : public base_it_t<image_file_header_t, file_header_it_t>
	{
		file_header_it_t()
			: base_it_t(nullptr) {}

	public:
		file_header_it_t(image_file_header_t* header)
			: base_it_t(header) {}
		_FILE_HEADER_ITEM_LIST(image_file_header_t, this->m_pdata->, _DEFINE_GETTER)
			_FILE_HEADER_ITEM_LIST(image_file_header_t, this->m_pdata->, _DEFINE_SETTER)
	};


#define _OPTIONAL_HEADER_ITEM_LIST(_Sd, _Sn, _M)                              \
	_M(_Sd, _Sn, Magic, magic)                                                \
	_M(_Sd, _Sn, MajorLinkerVersion, major_linker_version)                    \
	_M(_Sd, _Sn, MinorLinkerVersion, minor_linker_version)                    \
	_M(_Sd, _Sn, SizeOfCode, size_of_code);                                   \
	_M(_Sd, _Sn, SizeOfInitializedData, size_of_initialized_data)             \
	_M(_Sd, _Sn, SizeOfUninitializedData, size_of_uninitialized_data)         \
	_M(_Sd, _Sn, AddressOfEntryPoint, address_of_entry_point)                 \
	_M(_Sd, _Sn, BaseOfCode, base_of_code)                                    \
	_M(_Sd, _Sn, ImageBase, image_base)                                       \
	_M(_Sd, _Sn, SectionAlignment, section_alignment);                        \
	_M(_Sd, _Sn, FileAlignment, file_alignment);                              \
	_M(_Sd, _Sn, MajorOperatingSystemVersion, major_operating_system_version) \
	_M(_Sd, _Sn, MinorOperatingSystemVersion, minor_operating_system_version) \
	_M(_Sd, _Sn, MajorImageVersion, major_image_version)                      \
	_M(_Sd, _Sn, MinorImageVersion, minor_image_version)                      \
	_M(_Sd, _Sn, MajorSubsystemVersion, major_subsystem_version)              \
	_M(_Sd, _Sn, MinorSubsystemVersion, minor_subsystem_version)              \
	_M(_Sd, _Sn, Win32VersionValue, win32_version_value)                      \
	_M(_Sd, _Sn, SizeOfImage, size_of_image)                                  \
	_M(_Sd, _Sn, SizeOfHeaders, size_of_headers)                              \
	_M(_Sd, _Sn, CheckSum, check_sum)                                         \
	_M(_Sd, _Sn, Subsystem, subsystem)                                        \
	_M(_Sd, _Sn, DllCharacteristics, dll_characteristics)                     \
	_M(_Sd, _Sn, SizeOfStackReserve, size_of_stack_reserve)                   \
	_M(_Sd, _Sn, SizeOfStackCommit, size_of_stack_commit)                     \
	_M(_Sd, _Sn, SizeOfHeapReserve, size_of_heap_reserve)                     \
	_M(_Sd, _Sn, SizeOfHeapCommit, size_of_heap_commit)                       \
	_M(_Sd, _Sn, LoaderFlags, loader_flags)                                   \
	_M(_Sd, _Sn, NumberOfRvaAndSizes, number_of_rva_and_sizes)
#define optional_header_conditional_type(aw) std::conditional<aw == addr_width::x86, image_optional_header32_t, image_optional_header64_t>::type
	template <addr_width::type aw = addr_width::x64>
	class optional_header_it_t : public std::conditional<aw == addr_width::x86, base_it_t<image_optional_header32_t, optional_header_it_t<aw>>, base_it_t<image_optional_header64_t, optional_header_it_t<aw>> >::type
	{

		using _Header_type = optional_header_conditional_type(aw);
		optional_header_it_t()
			: base_it_t<_Header_type, optional_header_it_t>(nullptr) {}

	public:
		optional_header_it_t(_Header_type* header)
			: base_it_t<_Header_type, optional_header_it_t>(header) {}
		data_dir_it_t get_data_directory(uint32_t data_dir_enum)
		{
			if (data_dir_enum < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
				return &this->m_pdata->DataDirectory[data_dir_enum];
			return nullptr;
		}
		_OPTIONAL_HEADER_ITEM_LIST(_Header_type, this->m_pdata->, _DEFINE_GETTER)
		_OPTIONAL_HEADER_ITEM_LIST(_Header_type, this->m_pdata->, _DEFINE_SETTER)
	};


#define _THUNK_DATA_ITEM_LIST(_Sd, _Sn, _M)            \
	_M(_Sd, _Sn, u1.ForwarderString, forwarder_string) \
	_M(_Sd, _Sn, u1.Function, function)                \
	_M(_Sd, _Sn, u1.Ordinal, raw_ordinal)              \
	_M(_Sd, _Sn, u1.AddressOfData, address_of_data)
#define thunk_data_conditional_type(aw) std::conditional<aw == addr_width::x86, image_thunk_data32_t, image_thunk_data64_t>::type
	template <addr_width::type aw = addr_width::x64>
	class image_thunk_data_it_t : public std::conditional<aw == addr_width::x86, base_it_t<image_thunk_data32_t, image_thunk_data_it_t<aw>>, base_it_t<image_thunk_data64_t, image_thunk_data_it_t<aw>> >::type
	{
		using _Thunk_data_type = thunk_data_conditional_type(aw);
		using _Thunk_ordinal_type = std::conditional<aw == addr_width::x86, DWORD, ULONGLONG>::type;
		image_thunk_data_it_t()
			: base_it_t<_Thunk_data_type, image_thunk_data_it_t>(nullptr) {}

	public:
		image_thunk_data_it_t(_Thunk_data_type* thunk_data)
			: base_it_t<_Thunk_data_type, image_thunk_data_it_t>(thunk_data) {}
		bool is_ordinal() const
		{
			if constexpr (aw == addr_width::x86)
				return (get_raw_ordinal() & IMAGE_ORDINAL_FLAG32);
			return (get_raw_ordinal() & IMAGE_ORDINAL_FLAG64);
		}
		bool is_null()
		{
			return (get_address_of_data() == 0);
		}
		uint16_t get_masked_ordinal()
		{
			if constexpr (aw == addr_width::x86)
				return IMAGE_ORDINAL32(get_raw_ordinal());
			return IMAGE_ORDINAL64(get_raw_ordinal());
		}
		_THUNK_DATA_ITEM_LIST(_Thunk_data_type, this->m_pdata->, _DEFINE_GETTER)
			_THUNK_DATA_ITEM_LIST(_Thunk_data_type, this->m_pdata->, _DEFINE_SETTER)
	};


#define _TLS_DIR_ITEM_LIST(_Sd, _Sn, _M)                           \
	_M(_Sd, _Sn, StartAddressOfRawData, start_address_of_raw_data) \
	_M(_Sd, _Sn, EndAddressOfRawData, end_address_of_raw_data)     \
	_M(_Sd, _Sn, AddressOfIndex, address_of_index)                 \
	_M(_Sd, _Sn, AddressOfCallBacks, address_of_call_backs)        \
	_M(_Sd, _Sn, SizeOfZeroFill, size_of_zero_fill)                \
	_M(_Sd, _Sn, Characteristics, characteristics)                 \
	_M(_Sd, _Sn, Reserved0, reserved0)                             \
	_M(_Sd, _Sn, Alignment, alignment)                             \
	_M(_Sd, _Sn, Reserved1, reserved1)
#define tls_conditional_type(aw) std::conditional<aw == addr_width::x86, image_tls_dir32_t, image_tls_dir64_t>::type
	template <addr_width::type aw = addr_width::x64>
	class image_tls_dir_it_t : public std::conditional<aw == addr_width::x86, base_it_t<image_tls_dir32_t, image_tls_dir_it_t<aw>>, base_it_t<image_tls_dir64_t, image_tls_dir_it_t<aw>>>::type
	{
		using _Tls_dir_type = tls_conditional_type(aw);
		image_tls_dir_it_t()
			: base_it_t<_Tls_dir_type, image_tls_dir_it_t>(nullptr) {}

	public:
		image_tls_dir_it_t(_Tls_dir_type* tls_dir)
			: base_it_t<_Tls_dir_type, image_tls_dir_it_t>(tls_dir) {}
		_TLS_DIR_ITEM_LIST(_Tls_dir_type, this->m_pdata->, _DEFINE_GETTER)
			_TLS_DIR_ITEM_LIST(_Tls_dir_type, this->m_pdata->, _DEFINE_SETTER)
	};


#define _SECTION_HEADER_ITEM_LIST(_Sd, _Sn, _M)                 \
	_M(_Sd, _Sn, Misc.PhysicalAddress, physical_address)        \
	_M(_Sd, _Sn, Misc.VirtualSize, virtual_size)                \
	_M(_Sd, _Sn, VirtualAddress, virtual_address)               \
	_M(_Sd, _Sn, SizeOfRawData, size_of_raw_data)               \
	_M(_Sd, _Sn, PointerToRawData, pointer_to_raw_data)         \
	_M(_Sd, _Sn, PointerToRelocations, pointer_to_relocations)  \
	_M(_Sd, _Sn, PointerToLinenumbers, pointer_to_line_numbers) \
	_M(_Sd, _Sn, NumberOfRelocations, number_of_relocations)    \
	_M(_Sd, _Sn, NumberOfLinenumbers, number_of_line_numbers)   \
	_M(_Sd, _Sn, Characteristics, characteristics)
	class image_section_header_it_t : public base_it_t<image_section_header_t, image_section_header_it_t>
	{
		image_section_header_it_t()
			: base_it_t(nullptr) {}

	public:
		image_section_header_it_t(image_section_header_t* header)
			: base_it_t(header) {}

		bool compare_name(std::string const& str)
		{
			char temp[9];
			for (uint32_t i = 0; i < 9; i++)
				temp[i] = '\0';
			memcpy(temp, get_name(), 8);

			return (str == temp);
		}
		uint8_t* get_name() { return this->m_pdata->Name; }
		void set_name(uint8_t* new_name, uint32_t name_length)
		{
			uint32_t new_length = min(name_length, IMAGE_SIZEOF_SHORT_NAME);
			*(uint64_t*)this->m_pdata->Name = 0;
			for (uint32_t i = 0; i < new_length; i++)
				this->m_pdata->Name[i] = new_name[i];
		}
		_SECTION_HEADER_ITEM_LIST(image_section_header_t, this->m_pdata->, _DEFINE_GETTER)
			_SECTION_HEADER_ITEM_LIST(image_section_header_t, this->m_pdata->, _DEFINE_SETTER)
	};


#define _IMPORT_DESCRIPTOR_ITEM_LIST(_Sd, _Sn, _M)         \
	_M(_Sd, _Sn, OriginalFirstThunk, original_first_thunk) \
	_M(_Sd, _Sn, TimeDateStamp, time_date_stamp)           \
	_M(_Sd, _Sn, ForwarderChain, forwarder_chain)          \
	_M(_Sd, _Sn, Name, name)                               \
	_M(_Sd, _Sn, FirstThunk, first_thunk)
	class image_import_descriptor_it_t : public base_it_t<image_import_descriptor_t, image_import_descriptor_it_t>
	{
		image_import_descriptor_it_t()
			: base_it_t(nullptr) {}

	public:
		image_import_descriptor_it_t(image_import_descriptor_t* descriptor)
			: base_it_t(descriptor) {}

		bool is_null()
		{
			return (get_original_first_thunk() == 0 &&
				get_time_date_stamp() == 0 &&
				get_forwarder_chain() == 0 &&
				get_name() == 0 &&
				get_first_thunk() == 0);
		}

		_IMPORT_DESCRIPTOR_ITEM_LIST(image_import_descriptor_t, this->m_pdata->, _DEFINE_GETTER)
			_IMPORT_DESCRIPTOR_ITEM_LIST(image_import_descriptor_t, this->m_pdata->, _DEFINE_SETTER)
	};

#define _EXPORT_DESCRIPTOR_ITEM_LIST(_Sd, _Sn, _M)         \
	_M(_Sd, _Sn, Characteristics, characteristics)         \
	_M(_Sd, _Sn, TimeDateStamp, time_date_stamp)           \
	_M(_Sd, _Sn, MajorVersion, major_version)              \
	_M(_Sd, _Sn, MinorVersion, minor_version)              \
	_M(_Sd, _Sn, Name, name)                               \
	_M(_Sd, _Sn, Base, base)                               \
	_M(_Sd, _Sn, NumberOfFunctions, number_of_functions)   \
	_M(_Sd, _Sn, NumberOfNames, number_of_names)           \
	_M(_Sd, _Sn, AddressOfFunctions, address_of_functions) \
	_M(_Sd, _Sn, AddressOfNames, address_of_names)         \
	_M(_Sd, _Sn, AddressOfNameOrdinals, address_of_name_ordinals)
	class image_export_directory_it_t : public base_it_t<image_export_dir_t, image_export_directory_it_t>
	{
		image_export_directory_it_t()
			: base_it_t(nullptr) {}

	public:
		image_export_directory_it_t(image_export_dir_t* dir)
			: base_it_t(dir) {}

		_EXPORT_DESCRIPTOR_ITEM_LIST(image_export_dir_t, this->m_pdata->, _DEFINE_GETTER)
			_EXPORT_DESCRIPTOR_ITEM_LIST(image_export_dir_t, this->m_pdata->, _DEFINE_SETTER)
	};

#define _RUNTIME_FUNCTION_ITEM_LIST(_Sd, _Sn, _M)			\
	_M(_Sd, _Sn, BeginAddress, begin_address)				\
	_M(_Sd, _Sn, EndAddress, end_address)					\
	_M(_Sd, _Sn, UnwindInfoAddress, unwindw_info_address)	\
	_M(_Sd, _Sn, UnwindData, unwind_data)
	class image_runtime_function_it_t : public base_it_t<image_runtime_function_entry_t, image_runtime_function_it_t>
	{
		image_runtime_function_it_t()
			: base_it_t(nullptr) {}

	public:
		image_runtime_function_it_t(image_runtime_function_entry_t* entry)
			: base_it_t(entry) {}

		bool is_null()
		{
			return (get_begin_address() == 0 && get_end_address() == 0 && get_unwindw_info_address() == 0);
		}
		_RUNTIME_FUNCTION_ITEM_LIST(image_runtime_function_entry_t, this->m_pdata->, _DEFINE_GETTER)
			_RUNTIME_FUNCTION_ITEM_LIST(image_runtime_function_entry_t, this->m_pdata->, _DEFINE_SETTER)
	};

	struct unwind_info
	{
		uint8_t version : 3;				//0
		uint8_t flags : 5;					//
		uint8_t size_of_prolog;				//1
		uint8_t unwind_code_count;			//2
		uint8_t frame_register : 4;			//
		uint8_t frame_register_offset : 4;	//3
	};
	struct unwind_code
	{
		uint8_t offset_in_prolog;
		uint8_t operation_code : 4;
		uint8_t operation_info : 4;
	};

	int temp = sizeof(unwind_info);


#define reloc_block_size(Reloc_count) \
	align_up(sizeof image_base_relocation_t + (Reloc_count * sizeof(uint16_t)), 32)
#define reloc_block_pad_count(Reloc_count) \
	(reloc_block_size(Reloc_count) -	\
	(sizeof image_base_relocation_t + (Reloc_count * sizeof(uint16_t)))	/				\
	sizeof uint16_t)

#define _BASE_RELOCATION_ITEM_LIST(_Sd, _Sn, _M)		\
	_M(_Sd, _Sn, VirtualAddress, virtual_address)		\
	_M(_Sd, _Sn, SizeOfBlock, size_of_block)
	class image_base_reloc_block_it_t : public base_it_t<image_base_relocation_t, image_base_reloc_block_it_t>
	{
		image_base_reloc_block_it_t()
			: base_it_t(nullptr) {}

	public:
		image_base_reloc_block_it_t(image_base_relocation_t* entry)
			: base_it_t(entry) {}

		uint32_t get_num_of_relocs()
		{
			return ((get_size_of_block() - sizeof(image_base_relocation_t)) / 2);
		}
		bool is_null()
		{
			return (get_size_of_block() == 0 && get_virtual_address() == 0);
		}

		_BASE_RELOCATION_ITEM_LIST(image_base_relocation_t, this->m_pdata->, _DEFINE_GETTER)
			_BASE_RELOCATION_ITEM_LIST(image_base_relocation_t, this->m_pdata->, _DEFINE_SETTER)
	};
	const char* base_reloc_type_name_map[] = {
		"IMAGE_REL_BASED_ABSOLUTE",
		"IMAGE_REL_BASED_HIGH",
		"IMAGE_REL_BASED_LOW",
		"IMAGE_REL_BASED_HIGHLOW",
		"IMAGE_REL_BASED_HIGHADJ",
		"IMAGE_REL_BASED_MACHINE_SPECIFIC_5",
		"IMAGE_REL_BASED_RESERVED",
		"IMAGE_REL_BASED_MACHINE_SPECIFIC_7",
		"IMAGE_REL_BASED_MACHINE_SPECIFIC_8",
		"IMAGE_REL_BASED_MACHINE_SPECIFIC_9",
		"IMAGE_REL_BASED_DIR64",
	};
	class image_base_reloc_offset_it_t : public base_it_t<uint16_t, image_base_reloc_offset_it_t>
	{
		image_base_reloc_offset_it_t()
			: base_it_t(nullptr) {}

	public:
		image_base_reloc_offset_it_t(uint16_t* entry)
			: base_it_t(entry) {}

		uint8_t get_type()
		{
			return ((*this->m_pdata) >> 0xC);
		}
		void set_type(uint8_t type)
		{
			*this->m_pdata = ((*this->m_pdata & 0xFFF) | ((type & 0xF) << 0xC));
		}
		uint16_t get_offset()
		{
			return (*this->m_pdata & 0xFFF);
		}
		void set_offset(uint16_t offset)
		{
			*this->m_pdata = ((*this->m_pdata & 0xF000) | (offset & 0xFFF));
		}
		std::string get_type_name()
		{
			return base_reloc_type_name_map[get_type()];
		}
	};

	// This is the base class that describes data directories. All of them inherit from this
	//
	class data_directory_ir_t
	{
	protected:
		// Not all data directories are present in the binary.
		//
		bool m_is_present;

		// This is the index of a section_ir_t inside of binary_t::_default_sections
		//
		uint32_t m_target_section;

	public:
		data_directory_ir_t()
			: m_is_present(false),
			m_target_section(0) {}

		bool is_present() const { return m_is_present; }
		void set_is_present(bool state) { m_is_present = state; }

		uint32_t get_target_section() const { return m_target_section; }
		void set_target_section(uint32_t target_index) { m_target_section = target_index; }

		// virtual void append_to_vec(byte_vector& vec) const = 0;
	};

	class import_t
	{
		// using _Entry_type = std::conditional<aw == addr_width::x86, DWORD, ULONGLONG>::type;

	public:
		const std::string import_name;
		const uint16_t ordinal;
		const bool is_ordinal;

		// This is a symbol to the overwritten thunk data table.
		// The offset of the thunk_data struct within the binary gets put here once its placed.
		//
		const uint32_t thunk_symbol;

		// Initializer that constructs string import.
		//
		explicit import_t(uint16_t hint, char* name, uint32_t symbol)
			: ordinal(hint),
			import_name(name),
			is_ordinal(false),
			thunk_symbol(symbol) {}

		// Initializer for ordinals.
		//
		explicit import_t(uint16_t ordinal, uint32_t symbol)
			: ordinal(ordinal),
			import_name(""),
			is_ordinal(true),
			thunk_symbol(symbol) {}

		import_t(import_t const& to_copy)
			: ordinal(to_copy.ordinal),
			import_name(to_copy.import_name),
			is_ordinal(to_copy.is_ordinal),
			thunk_symbol(to_copy.thunk_symbol) {}
	};
	template <addr_width::type aw = addr_width::x64>
	class import_module_t : public data_directory_ir_t
	{
	public:
		std::vector<import_t> entries;
		const std::string module_name;

		explicit import_module_t(std::string const& name)
			: module_name(name) {}
		import_module_t(import_module_t<aw> const& to_copy)
			: module_name(to_copy.module_name)
		{
			for (import_t const& entry : to_copy.entries)
				entries.push_back(entry);
		}

		void add_ordinal_import(uint16_t ordinal, uint32_t thunk_symbol)
		{
			entries.emplace_back(ordinal, thunk_symbol);
		}
		void add_named_import(uint16_t hint, char* name, uint32_t thunk_symbol)
		{
			entries.emplace_back(hint, name, thunk_symbol);
		}

		// This function builds a table of image_import_by_name_t structures and an associated vector of uint32_t offsets within said structure.
		std::pair<std::vector<char>, std::vector<uint32_t>> build_string_table() const
		{
			std::vector<char> string_table;
			std::vector<uint32_t> offset_table;

			string_table.reserve(entries.size() * 10);

			for (import_t const& entry : entries)
			{
				offset_table.push_back(string_table.size());
				string_table.push_back(0);
				string_table.push_back(0);
				for (char ch : entry.import_name)
					string_table.push_back(ch);
				string_table.push_back(0);
			}
			return { string_table, offset_table };
		}
	};

	class export_t
	{
	public:
		const uint64_t rva;

		const std::string export_name;
		const uint16_t ordinal;

		// This symbol is written to by
		//
		const uint32_t symbol;

		// Initializer that constructs string import.
		//
		explicit export_t(std::string const& name, uint32_t sym, uint64_t virt_addr)
			: export_name(name),
			symbol(sym),
			ordinal(0),
			rva(virt_addr)
		{}
		explicit export_t(uint32_t ord, uint32_t sym, uint64_t virt_addr)
			: export_name(""),
			symbol(sym),
			ordinal(ord),
			rva(virt_addr)
		{}
		export_t(export_t const& to_copy)
			: export_name(to_copy.export_name),
			symbol(to_copy.symbol),
			ordinal(to_copy.ordinal),
			rva(to_copy.rva)
		{}

		bool is_ordinal()
		{
			return (ordinal != 0);
		}
	};

	class exports_t
	{
	public:
		std::vector<export_t> entries;

		explicit exports_t() {}

		exports_t(exports_t const& to_copy)
		{
			for (export_t const& entry : to_copy.entries)
				entries.push_back(entry);
		}

		void add_ordinal_export(uint32_t ordinal, uint32_t symbol, uint64_t virt_addr)
		{
			entries.emplace_back(ordinal, symbol, virt_addr);
		}
		void add_named_export(char* name, uint32_t symbol, uint64_t virt_addr)
		{
			entries.emplace_back(name, symbol, virt_addr);
		}
	};

	template <addr_width::type aw = addr_width::x64>
	class binary_t
	{
	public:
		// Pointer to the image mapping as if it were to be executed.
		//
		uint8_t* mapped_image;

		bin_data_table_t* data_table;

		// Header iterators/interfaces
		//
		dos_header_it_t dos_header;
		file_header_it_t file_header;
		optional_header_it_t<aw> optional_header;

		// These are the sections header interfaces from the original binary.
		//
		std::vector<image_section_header_it_t> section_headers;

		std::vector<import_module_t<aw>> m_imports;
		exports_t m_exports;

		bool relocs_changed;
		std::vector<std::pair<uint8_t, uint32_t>> base_relocs;

		template<typename Ptr_type>
		Ptr_type* rva_as(uint32_t rva)
		{
			return reinterpret_cast<Ptr_type*>(mapped_image + rva);
		}
	public:
		binary_t()
			: optional_header(nullptr),
			file_header(nullptr),
			dos_header(nullptr)
		{}
		~binary_t() {}

		bool is_rva_in_executable_section(uint64_t rva)
		{
			for (auto& section : section_headers)
			{
				if (auto virt_addr = section.get_virtual_address();
					rva >= virt_addr &&
					rva < virt_addr + section.get_virtual_size() &&
					section.get_characteristics() & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
					)
				{
					return true;
				}
			}
			return false;
		}

		bool is_rva_in_iat(uint64_t rva)
		{
			return false;
		}

		void update_header_iterators(uint8_t* base)
		{
			dos_header.set(base);
			file_header.set(base + dos_header.get_lfanew() + sizeof uint32_t);
			optional_header.set(base + dos_header.get_lfanew() + sizeof uint32_t + sizeof image_file_header_t);

			section_headers.clear();

			uint8_t* section_header_base = reinterpret_cast<uint8_t*>(optional_header.get()) + file_header.get_size_of_optional_header();
			for (uint32_t i = 0; i < file_header.get_number_of_sections(); i++)
			{
				section_headers.emplace_back(reinterpret_cast<image_section_header_t*>(section_header_base + (i * sizeof image_section_header_t)));
			}
		}

		// These are here because i'm not certain that the sections are required to always be in order
		//
		uint32_t get_max_virt_addr()
		{
			uint32_t max_addr = 0;
			for (auto& sec : section_headers)
			{
				if (uint32_t sec_end = sec.get_virtual_address() + sec.get_virtual_size(); sec_end > max_addr)
					max_addr = sec_end;
			}
			return max_addr;
		}
		uint32_t get_max_file_addr()
		{
			uint32_t max_addr = 0;
			for (auto& sec : section_headers)
			{
				if (uint32_t sec_end = sec.get_pointer_to_raw_data() + sec.get_size_of_raw_data(); sec_end > max_addr)
					max_addr = sec_end;
			}
			return max_addr;
		}
		uint32_t get_lowest_section_start()
		{
			uint32_t min_addr = 0xFFFFFFFF; // section_headers.front().get_pointer_to_raw_data();
			for (auto& sec : section_headers)
			{
				// Have to check for >0 because of some .bss section bs
				if (uint32_t sec_start = sec.get_pointer_to_raw_data(); sec_start < min_addr && sec_start > 0)
					min_addr = sec_start;
			}
			return min_addr;
		}

		template<typename It_type>
		It_type get_it(uint64_t rva)
		{
			return It_type(reinterpret_cast<It_type::My_type*>(mapped_image + rva));
		}

		// If we were to append another section, this routine tells us its rva
		//
		uint32_t next_section_rva()
		{
			return align_up(get_max_virt_addr(), optional_header.get_section_alignment());
		}

		uint32_t append_section(std::string const& name, uint32_t section_size, uint32_t characteristics, bool is_code = false, bool is_idata = false, bool is_udata = false)
		{
			// Make sure there is enough space for another section header.
			//
			if (auto header_size = align_up(
				dos_header.get_lfanew() +
				sizeof uint32_t +
				sizeof image_file_header_t +
				file_header.get_size_of_optional_header() +
				sizeof image_section_header_t * (file_header.get_number_of_sections() + 1),
				optional_header.get_file_alignment()); header_size > get_lowest_section_start()
				)
			{
				std::printf("Not enough space to append section. %016X %X\n", header_size, get_lowest_section_start());
				return 0;
			}

			auto last_section = section_headers.back();
			uint32_t virt_addr = align_up(get_max_virt_addr(), optional_header.get_section_alignment());
			uint32_t virt_size = section_size;
			uint32_t aligned_virt_size = align_up(virt_size, optional_header.get_section_alignment());

			uint32_t file_addr = align_up(get_max_file_addr(), optional_header.get_file_alignment());
			uint32_t file_size = align_up(section_size, optional_header.get_file_alignment());

			uint8_t* new_mapped_image = new uint8_t[optional_header.get_size_of_image() + align_up(virt_size, optional_header.get_section_alignment())];
			std::memcpy(new_mapped_image, mapped_image, optional_header.get_size_of_image());
			delete[] mapped_image;
			mapped_image = new_mapped_image;

			update_header_iterators(mapped_image);

			// Allocate new section header and increment section count
			uint32_t section_count = file_header.get_number_of_sections();
			section_headers.emplace_back(section_headers.front().get() + section_count);
			file_header.set_number_of_sections(section_count + 1);

			// Update sizes in headers
			//
			optional_header.set_size_of_image(optional_header.get_size_of_image() + aligned_virt_size);

			optional_header.set_size_of_headers(align_up(
				dos_header.get_lfanew() +
				sizeof uint32_t +
				sizeof image_file_header_t +
				file_header.get_size_of_optional_header() +
				sizeof image_section_header_t * file_header.get_number_of_sections(),
				optional_header.get_file_alignment()
			));

			// Tested and these are ignored by loader, I think they were used to create the sections cs ds at some point? no clue.
			//
			if (is_code)
				optional_header.set_size_of_code(optional_header.get_size_of_code() + aligned_virt_size);
			else if (is_idata)
				optional_header.set_size_of_initialized_data(optional_header.get_size_of_initialized_data() + aligned_virt_size);
			else if (is_udata)
				optional_header.set_size_of_uninitialized_data(optional_header.get_size_of_uninitialized_data() + aligned_virt_size);


			// Update the section header
			//
			auto& cur_section = section_headers.back();
			for (uint8_t i = 0; i < 8; i++)
			{
				if (i < name.size())
					cur_section.get()->Name[i] = name[i];
				else
					cur_section.get()->Name[i] = 0;
			}
			cur_section.set_pointer_to_raw_data(file_addr);
			cur_section.set_size_of_raw_data(file_size);
			cur_section.set_virtual_address(virt_addr);
			cur_section.set_virtual_size(virt_size);
			cur_section.set_characteristics(characteristics);

			cur_section.set_pointer_to_relocations(0);
			cur_section.set_number_of_relocations(0);
			cur_section.set_pointer_to_line_numbers(0);
			cur_section.set_number_of_line_numbers(0);

			data_table->resize_image_table(optional_header.get_size_of_image());

			// Update symbol table if this section is executable
			//
			if (characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
			{
				for (uint32_t i = 0; i < section_size; i++)
				{
					data_table->unsafe_get_symbol_for_rva(virt_addr + i).set_flag(bin_data_flag::executable);
				}
			}

			return virt_addr;
		}

		void rebuild_base_reloc_section()
		{
			if (!base_relocs.size() || !relocs_changed)
				return;

			std::sort(base_relocs.begin(), base_relocs.end(), [](std::pair<uint8_t, uint32_t> const& left, std::pair<uint8_t, uint32_t> const& right)
				{
					return (left.second < right.second);
				});

			std::vector<
				std::pair<
					uint32_t, 
					std::vector<
						std::pair<
							uint8_t, 
							uint16_t
						> 
					> 
				>
			> reloc_blocks;
			
			
			uint32_t cur_base = base_relocs.front().second;
			reloc_blocks.emplace_back(cur_base, std::vector<std::pair<uint8_t, uint16_t>>());
			for (auto const& reloc : base_relocs)
			{
				if (auto offset = reloc.second - cur_base; offset < 0x1000)
					reloc_blocks.back().second.emplace_back(reloc.first, offset);
				else
				{
					cur_base = reloc.second;
					reloc_blocks.emplace_back(cur_base, std::vector<std::pair<uint8_t, uint16_t>>());
					reloc_blocks.back().second.emplace_back(reloc.first, 0);
				}
			}

			uint32_t total_reloc_section_size = 0;
			for (auto const& block : reloc_blocks)
			{
				total_reloc_section_size += reloc_block_size(block.second.size());
			}
			//printf("The reloc section is %X and was %X\n", total_reloc_section_size, optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).get_size());
			//printf("Counts of relocs %X %X %X\n", entry_count, base_relocs.size(), reloc_blocks.size());

			// Space for the null section at the end
			//
			total_reloc_section_size += sizeof image_base_relocation_t;

			image_section_header_it_t reloc_section_header(nullptr);
			for (auto sec : section_headers)
			{
				if (sec.compare_name(".reloc"))
				{
					reloc_section_header.set(sec.get());
					break;
				}
			}

			uint32_t null_name = 0;
			reloc_section_header.set_name(reinterpret_cast<uint8_t*>(&null_name), 8);

			auto new_reloc_section_rva = append_section(".reloc", total_reloc_section_size, reloc_section_header.get_characteristics());

			optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).set_size(total_reloc_section_size);
			optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).set_virtual_address(new_reloc_section_rva);

			for (auto const& block : reloc_blocks)
			{
				
				image_base_reloc_block_it_t block_header_it(reinterpret_cast<image_base_relocation_t*>(mapped_image + new_reloc_section_rva));
				block_header_it.set_size_of_block(reloc_block_size(block.second.size()));
				block_header_it.set_virtual_address(block.first);

				image_base_reloc_offset_it_t offset_it(reinterpret_cast<uint16_t*>(mapped_image + new_reloc_section_rva + sizeof image_base_relocation_t));
				for (uint32_t i = 0; i < block.second.size(); ++i)
				{
					offset_it[i].set_type(block.second[i].first);
					offset_it[i].set_offset(block.second[i].second);
				}

				for (uint32_t i = 0; i < reloc_block_pad_count(block.second.size()); ++i)
				{
					offset_it[block.second.size() + i].set_type(IMAGE_REL_BASED_ABSOLUTE);
					offset_it[block.second.size() + i].set_offset(0);
				}
				new_reloc_section_rva += reloc_block_size(block.second.size());
			}
			image_base_reloc_block_it_t null_block_header(reinterpret_cast<image_base_relocation_t*>(mapped_image + new_reloc_section_rva));
			null_block_header.set_size_of_block(0);
			null_block_header.set_virtual_address(0);
		}
		void remap_reloc(uint32_t original_rva, uint32_t new_rva, uint8_t reloc_type)
		{
			relocs_changed = true;
			for (auto it = base_relocs.begin(); it != base_relocs.end(); ++it)
				if (it->second == original_rva)
					base_relocs.erase(it);

			base_relocs.emplace_back(reloc_type, new_rva);
		}

		bool from_file(std::string const& file_path)
		{
			if (!std::filesystem::exists(file_path))
				return false;

			std::ifstream file(file_path, std::ios::binary);
			if (!file.good())
				return false;

			file.seekg(0, std::ios::end);
			uint32_t file_size = static_cast<uint32_t>(file.tellg());
			file.seekg(0, std::ios::beg);
			uint8_t* data = new uint8_t[file_size];
			if (!data)
			{
				file.close();
				return false;
			}

			file.read((PCHAR)data, file_size);
			file.close();

			bool ret = map_image(data, file_size);

			return ret;
		}
		bool to_file(std::string const& file_path)
		{
			std::ofstream file(file_path, std::ios::binary);
			if (!file.good())
				return false;

			std::printf("wrote it.\n");
			uint32_t data_size = 0;
			uint8_t* data = unmap_image(data_size);

			file.write((char*)data, data_size);
			file.close();

			return true;
		}
		bool map_image(uint8_t* image_base, uint32_t image_size)
		{
			if (image_size < sizeof image_dos_header_t)
				return false;

			dos_header.set(image_base);
			if (dos_header.get_magic() != IMAGE_DOS_SIGNATURE)
				return false;

			uint8_t* new_header_addr = image_base + dos_header.get_lfanew();

			if (image_size < dos_header.get_lfanew() + sizeof image_nt_headers64_t ||
				*(uint32_t*)new_header_addr != IMAGE_NT_SIGNATURE)
				return false;

			file_header.set(new_header_addr + sizeof uint32_t);

			optional_header.set(new_header_addr + sizeof uint32_t + sizeof image_file_header_t);

			if ((optional_header.get_magic() == IMAGE_NT_OPTIONAL_HDR32_MAGIC && aw != addr_width::x86) ||
				(optional_header.get_magic() == IMAGE_NT_OPTIONAL_HDR64_MAGIC && aw != addr_width::x64))
				return false;

			data_table = new bin_data_table_t(optional_header.get_size_of_image(), 3000);

			// Enumerate all sections
			//
			{
				image_section_header_it_t section_header_it(reinterpret_cast<image_section_header_t*>(
					new_header_addr + offsetof(image_nt_headers64_t, OptionalHeader) + file_header.get_size_of_optional_header()));

				for (uint16_t i = 0; i < file_header.get_number_of_sections(); ++i)
				{
					section_headers.emplace_back(section_header_it[i]);

					if (section_header_it[i].get_characteristics() & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
					{
						data_table->unsafe_mark_range_as(
							section_header_it[i].get_virtual_address(), 
							section_header_it[i].get_virtual_size(),
							bin_data_flag::executable
						);
					}
				}
			}

			if (!section_headers.size())
			{
				std::printf("Image has no sections.\n");
				return false;
			}

			// Build the mapped image. Where sections are at their real rvas
			//
			{
				mapped_image = new uint8_t[optional_header.get_size_of_image()];

				// Copy the headers over.
				//
				std::memcpy(mapped_image, image_base, optional_header.get_size_of_headers());

				update_header_iterators(mapped_image);

				// Map the sections
				//
				for (auto& section : section_headers)
				{
					std::memcpy(mapped_image + section.get_virtual_address(), image_base + section.get_pointer_to_raw_data(), section.get_size_of_raw_data());
				}
			}

			// Insert runtime function data into the symbol table
			//
			for (auto runtime_func_it = get_it<image_runtime_function_it_t>(optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).get_virtual_address());
				!runtime_func_it.is_null(); ++runtime_func_it)
			{
				data_table->set_func_data_and_start(runtime_func_it.get_begin_address(), reinterpret_cast<uint64_t>(runtime_func_it.get()) - reinterpret_cast<uint64_t>(mapped_image));
			}

			// Insert reloc data into symbol table
			//
			relocs_changed = false;
			if (0 && !(file_header.get_characteristics() & IMAGE_FILE_RELOCS_STRIPPED) && optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).get_size())
			{
				auto block_it = get_it<image_base_reloc_block_it_t>(optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC).get_virtual_address());
				while (!block_it.is_null())
				{
					image_base_reloc_offset_it_t it(reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(block_it.get()) + sizeof image_base_relocation_t));

					auto num_relocs = block_it.get_num_of_relocs();
					auto virt_addr = block_it.get_virtual_address();
					for (uint32_t i = 0; i < num_relocs; ++i)
					{
						auto reloc_addr = virt_addr + it[i].get_offset();
						base_relocs.emplace_back(it[i].get_type(), reloc_addr);
						data_table->unsafe_get_symbol_for_rva(reloc_addr).mark_as_reloc(it[i].get_type());
					}

					block_it.set(reinterpret_cast<uint8_t*>(block_it.get()) + block_it.get_size_of_block());
				}
			}



			// Fill normal imports
			//
			if (optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).get_size())
			{
				for (auto import_descriptor_it = get_it< image_import_descriptor_it_t>(optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).get_virtual_address());
					!import_descriptor_it.is_null(); ++import_descriptor_it)
				{
					m_imports.emplace_back(rva_as<char>(import_descriptor_it.get_name()));

					//std::printf("Module Name: %s\n", m_imports.back().module_name.data());

					for (auto thunk_data_it = get_it<image_thunk_data_it_t<aw>>(import_descriptor_it.get_original_first_thunk());
						!thunk_data_it.is_null(); ++thunk_data_it)
					{
						uint32_t symbol_index = data_table->unsafe_get_symbol_index_for_rva(
							static_cast<uint64_t>(reinterpret_cast<uint8_t*>(thunk_data_it.get()) - mapped_image)
						);

						if (!thunk_data_it.is_ordinal())
						{
							image_import_by_name_t* import_name = rva_as<image_import_by_name_t>(thunk_data_it.get_address_of_data());

							m_imports.back().add_named_import(
								import_name->Hint,
								import_name->Name,
								symbol_index);

							//std::printf("\tImport name %s\n", import_name->Name);
						}
						else
						{
							m_imports.back().add_ordinal_import(
								thunk_data_it.get_masked_ordinal(),
								symbol_index);
						}
					}
				}


			}

			if (optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).get_size())
			{
				std::printf("Found delay load data dir.\n");
			}

			if (optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT).get_size())
			{
				std::printf("Found bound data dir.\n");
			}

			if (optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT).get_size())
			{
				auto export_dir = get_it<image_export_directory_it_t>(optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT).get_virtual_address());

				uint32_t* name_address_table = rva_as<uint32_t>(export_dir.get_address_of_names());
				uint32_t* export_address_table = rva_as<uint32_t>(export_dir.get_address_of_functions());
				uint16_t* name_ordinal_table = rva_as<uint16_t>(export_dir.get_address_of_name_ordinals());

				std::set<uint16_t> ordinals;
				for (uint32_t i = 0; i < export_dir.get_number_of_functions(); ++i)
					ordinals.emplace_hint(ordinals.end(), i);

				for (uint32_t i = 0; i < export_dir.get_number_of_names(); i++)
				{
					char* name = rva_as<char>(name_address_table[i]);
					uint16_t name_ordinal = name_ordinal_table[i];

					uint32_t export_rva = export_address_table[name_ordinal];

					m_exports.add_named_export(name,
						data_table->unsafe_get_symbol_index_for_rva(
							export_rva, bin_data_flag::is_export
						),
						export_rva
					);

					ordinals.erase(name_ordinal);
				}

				for (uint16_t ordinal : ordinals)
				{
					uint32_t export_rva = export_address_table[ordinal];

					m_exports.add_ordinal_export(ordinal,
						data_table->unsafe_get_symbol_index_for_rva(
							export_rva, bin_data_flag::is_export
						),
						export_rva
					);
				}
			}


			// USE SEH TABLES TO FIND FUNCTIONS.



			return true;
		}
		uint8_t* unmap_image(uint32_t& raw_image_size)
		{
			// Rebuild reloc section
			//
			rebuild_base_reloc_section();

			raw_image_size = get_max_file_addr();

			uint8_t* output_image = new uint8_t[raw_image_size];

			printf("Unmapping image of size %X.\n", raw_image_size);

			// Copy default headers
			//
			std::memcpy(output_image, mapped_image, optional_header.get_size_of_headers());

			// Remap iterators to this output
			//
			dos_header.set(output_image);
			file_header.set(output_image + dos_header.get_lfanew() + sizeof uint32_t);
			optional_header.set(output_image + dos_header.get_lfanew() + sizeof uint32_t + sizeof image_file_header_t);

			// Copy sections
			//
			for (auto& sec : section_headers)
			{
				std::memcpy(output_image + sec.get_pointer_to_raw_data(), mapped_image + sec.get_virtual_address(), sec.get_size_of_raw_data());
			}

			return output_image;
		}

		inline static addr_width::type deduce_address_width(std::string const& file_path)
		{
			if (!std::filesystem::exists(file_path))
				return addr_width::invalid;

			std::ifstream file(file_path, std::ios::binary);
			if (!file.good())
				return addr_width::invalid;

			file.seekg(0, std::ios::end);
			uint32_t file_size = static_cast<uint32_t>(file.tellg());
			file.seekg(0, std::ios::beg);

			if (file_size < 0x1000)
				return addr_width::invalid;

			uint8_t* data = new uint8_t[0x1000];
			if (!data)
			{
				file.close();
				return addr_width::invalid;
			}

			file.read((PCHAR)data, 0x1000);
			file.close();

			addr_width::type width = deduce_address_width(data, file_size);

			delete[] data;
			return width;
		}
		inline static addr_width::type deduce_address_width(uint8_t* image_data, uint32_t image_size)
		{
			if (image_size < sizeof image_dos_header_t)
				return addr_width::invalid;
			image_dos_header_t* dos_header = (image_dos_header_t*)image_data;
			if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
				return addr_width::invalid;

			image_nt_headers32_t* nt_headers = (image_nt_headers32_t*)(image_data + dos_header->e_lfanew);

			if (image_size < dos_header->e_lfanew + sizeof image_nt_headers32_t ||
				nt_headers->Signature != IMAGE_NT_SIGNATURE)
				return addr_width::invalid;

			if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				return addr_width::x86;
			else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				return addr_width::x64;

			return addr_width::invalid;
		}

		void print_section_info()
		{
			for (auto sec : section_headers)
				debug_print_section_info(sec.get());
		}

		inline static void debug_print_section_info(image_section_header_t* section_header)
		{
			char sec_name_buffer[IMAGE_SIZEOF_SHORT_NAME + 1];
			sec_name_buffer[IMAGE_SIZEOF_SHORT_NAME] = '\0';
			std::memcpy(sec_name_buffer, section_header->Name, IMAGE_SIZEOF_SHORT_NAME);

			std::printf("\nSection Name: %s\n", sec_name_buffer);
			std::printf("VirtualSize: 0x%X\n", section_header->Misc.VirtualSize);
			std::printf("VirtualAddress: 0x%X\n", section_header->VirtualAddress);
			std::printf("SizeOfRawData: 0x%X\n", section_header->SizeOfRawData);
			std::printf("PointerToRawData: 0x%X\n", section_header->PointerToRawData);
			std::printf("PointerToRelocations: 0x%X\n", section_header->PointerToRelocations);
			std::printf("PointerToLinenumbers: 0x%X\n", section_header->PointerToLinenumbers);
			std::printf("NumberOfRelocations: 0x%X\n", section_header->NumberOfRelocations);
			std::printf("NumberOfLinenumbers: 0x%X\n", section_header->NumberOfLinenumbers);
			std::printf("Characteristics: 0x%X\n\n", section_header->Characteristics);
		}
	};

}
