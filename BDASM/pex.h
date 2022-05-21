#pragma once

#include <Windows.h>
#include <string_view>
#include <string>
#include <vector>
#include <variant>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <type_traits>

#include "addr_width.h"
#include "symbol.h"

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


typedef std::vector<uint8_t> byte_vector;

#define _DEFINE_GETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) [[nodiscard]] __forceinline decltype(_Sd::_ItemName) get_##_RealName##() const
#define _DEFINE_SETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) __forceinline void set_##_RealName##(decltype(_Sd::_ItemName) value)

#define _DEFINE_GETTER(_Sd, _Sn, _ItemName, _RealName) \
	_DEFINE_GETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) { return _Sn##_ItemName; }
#define _DEFINE_SETTER(_Sd, _Sn, _ItemName, _RealName) \
	_DEFINE_SETTER_PROTO(_Sd, _Sn, _ItemName, _RealName) { _Sn##_ItemName = value; }

template <typename Class_type, typename Interface_type>
class base_interface_t
{
	base_interface_t()
		: m_pdata(nullptr) {}

protected:
	Class_type* m_pdata;

public:
	base_interface_t(Class_type* ptr)
		: m_pdata(ptr) {}
	base_interface_t(base_interface_t const& to_copy)
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
	Class_type* get()
	{
		return m_pdata;
	}
	uint8_t get_byte_ptr()
	{
		return reinterpret_cast<uint8_t*>(m_pdata);
	}
	Interface_type& operator++()
	{
		++m_pdata;
		return *static_cast<Interface_type*>(this);
	}
	[[nodiscard]] Interface_type operator++(int)
	{
		return Interface_type(m_pdata++);
	}
	Interface_type operator--()
	{
		--m_pdata;
		return *static_cast<Interface_type*>(this);
	}
	[[nodiscard]] Interface_type operator--(int)
	{
		return Interface_type(m_pdata--);
	}
	Interface_type operator[](uint32_t index)
	{
		return Interface_type(m_pdata + index);
	}
};

#define _DATA_DIR_ITEM_LIST(_Sd, _Sn, _M)          \
	_M(_Sd, _Sn, VirtualAddress, virtual_address); \
	_M(_Sd, _Sn, Size, size);
class data_dir_interface_t : public base_interface_t<image_data_dir_t, data_dir_interface_t>
{
	data_dir_interface_t()
		: base_interface_t(nullptr) {}

public:
	data_dir_interface_t(image_data_dir_t* raw_data)
		: base_interface_t(raw_data) {}
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
class dos_header_interface_t : public base_interface_t<image_dos_header_t, dos_header_interface_t>
{
	dos_header_interface_t()
		: base_interface_t(nullptr) {}

public:
	dos_header_interface_t(image_dos_header_t* raw_data)
		: base_interface_t(raw_data) {}
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
class file_header_interface_t : public base_interface_t<image_file_header_t, file_header_interface_t>
{
	file_header_interface_t()
		: base_interface_t(nullptr) {}

public:
	file_header_interface_t(image_file_header_t* header)
		: base_interface_t(header) {}
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
#define optional_header_conditional_type(Addr_width) std::conditional<Addr_width == address_width::x86, image_optional_header32_t, image_optional_header64_t>::type
template <address_width Addr_width = address_width::x64>
class optional_header_interface_t : public std::conditional<Addr_width == address_width::x86, base_interface_t<image_optional_header32_t, optional_header_interface_t<Addr_width>>, base_interface_t<image_optional_header64_t, optional_header_interface_t<Addr_width>>>::type
{
	
	using _Header_type = optional_header_conditional_type(Addr_width);
	optional_header_interface_t()
		: base_interface_t<_Header_type, optional_header_interface_t>(nullptr) {}

public:
	optional_header_interface_t(_Header_type* header)
		: base_interface_t<_Header_type, optional_header_interface_t>(header) {}
	data_dir_interface_t get_data_directory(uint32_t data_dir_enum)
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
#define thunk_data_conditional_type(Addr_width) std::conditional<Addr_width == address_width::x86, image_thunk_data32_t, image_thunk_data64_t>::type
template <address_width Addr_width = address_width::x64>
class image_thunk_data_interface_t : public std::conditional<Addr_width == address_width::x86, base_interface_t<image_thunk_data32_t, image_thunk_data_interface_t<Addr_width>>, base_interface_t<image_thunk_data64_t, image_thunk_data_interface_t<Addr_width>>>::type
{
	using _Thunk_data_type = thunk_data_conditional_type(Addr_width);
	using _Thunk_ordinal_type = std::conditional<Addr_width == address_width::x86, DWORD, ULONGLONG>::type;
	image_thunk_data_interface_t()
		: base_interface_t<_Thunk_data_type, image_thunk_data_interface_t>(nullptr) {}

public:
	image_thunk_data_interface_t(_Thunk_data_type* thunk_data)
		: base_interface_t<_Thunk_data_type, image_thunk_data_interface_t>(thunk_data) {}
	bool is_ordinal() const
	{
		if constexpr (Addr_width == address_width::x86)
			return (get_raw_ordinal() & IMAGE_ORDINAL_FLAG32);
		return (get_raw_ordinal() & IMAGE_ORDINAL_FLAG64);
	}
	bool is_null()
	{
		return (get_address_of_data() == 0);
	}
	uint16_t get_masked_ordinal()
	{
		if constexpr (Addr_width == address_width::x86)
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
#define tls_conditional_type(Addr_width) std::conditional<Addr_width == address_width::x86, image_tls_dir32_t, image_tls_dir64_t>::type
template <address_width Addr_width = address_width::x64>
class image_tls_dir_interface_t : public std::conditional<Addr_width == address_width::x86, base_interface_t<image_tls_dir32_t, image_tls_dir_interface_t<Addr_width>>, base_interface_t<image_tls_dir64_t, image_tls_dir_interface_t<Addr_width>>>::type
{
	using _Tls_dir_type = tls_conditional_type(Addr_width);
	image_tls_dir_interface_t()
		: base_interface_t<_Tls_dir_type, image_tls_dir_interface_t>(nullptr) {}

public:
	image_tls_dir_interface_t(_Tls_dir_type* tls_dir)
		: base_interface_t<_Tls_dir_type, image_tls_dir_interface_t>(tls_dir) {}
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
class image_section_header_interface_t : public base_interface_t<image_section_header_t, image_section_header_interface_t>
{
	image_section_header_interface_t()
		: base_interface_t(nullptr) {}

public:
	image_section_header_interface_t(image_section_header_t* header)
		: base_interface_t(header) {}

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
class image_import_descriptor_interface_t : public base_interface_t<image_import_descriptor_t, image_import_descriptor_interface_t>
{
	image_import_descriptor_interface_t()
		: base_interface_t(nullptr) {}

public:
	image_import_descriptor_interface_t(image_import_descriptor_t* descriptor)
		: base_interface_t(descriptor) {}

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
class image_export_directory_interface_t : public base_interface_t<image_export_dir_t, image_export_directory_interface_t>
{
	image_export_directory_interface_t()
		: base_interface_t(nullptr) {}

public:
	image_export_directory_interface_t(image_export_dir_t* dir)
		: base_interface_t(dir) {}

	_EXPORT_DESCRIPTOR_ITEM_LIST(image_export_dir_t, this->m_pdata->, _DEFINE_GETTER)
		_EXPORT_DESCRIPTOR_ITEM_LIST(image_export_dir_t, this->m_pdata->, _DEFINE_SETTER)
};



// Representation definitions for when we need our own representation.
//
class dos_header_rep_t : public dos_header_interface_t
{
	image_dos_header_t m_header;

public:
	explicit dos_header_rep_t()
		: dos_header_interface_t(&this->m_header) {}
	explicit dos_header_rep_t(dos_header_rep_t const& to_copy)
		: dos_header_interface_t(&this->m_header)
	{
		this->copy_from_data(to_copy.m_pdata);
	}
};
class file_header_rep_t : public file_header_interface_t
{
	image_file_header_t m_header;

public:
	explicit file_header_rep_t()
		: file_header_interface_t(&this->m_header) {}
	explicit file_header_rep_t(file_header_rep_t const& to_copy)
		: file_header_interface_t(&this->m_header)
	{
		this->copy_from_data(to_copy.m_pdata);
	}
};
template <address_width Addr_width = address_width::x64>
class optional_header_rep_t : public optional_header_interface_t<Addr_width>
{
	using _Header_type = std::conditional<Addr_width == address_width::x86, image_optional_header32_t, image_optional_header64_t>::type;
	_Header_type m_header;

public:
	explicit optional_header_rep_t()
		: optional_header_interface_t<Addr_width>(&this->m_header) {}
	explicit optional_header_rep_t(optional_header_rep_t const& to_copy)
		: optional_header_interface_t<Addr_width>(&this->m_header)
	{
		this->copy_from_data(to_copy.m_pdata);
	}
};
class section_header_rep_t : public image_section_header_interface_t
{
	image_section_header_t m_header;

public:
	byte_vector section_data;

	explicit section_header_rep_t()
		: image_section_header_interface_t(&this->m_header) {}

	explicit section_header_rep_t(uint8_t* image_base, image_section_header_interface_t section_header)
		: image_section_header_interface_t(&this->m_header)
	{
		this->copy_from_data(section_header.get());
		uint8_t* copy_start = image_base + section_header.get_pointer_to_raw_data();
		this->section_data.insert(this->section_data.begin(), copy_start, copy_start + section_header.get_size_of_raw_data());
	}

	explicit section_header_rep_t(section_header_rep_t const& to_copy)
		: image_section_header_interface_t(&this->m_header)
	{
		this->copy_from_data(to_copy.m_pdata);
		this->section_data.insert(this->section_data.begin(), to_copy.section_data.begin(), to_copy.section_data.end());
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

	// This is the index of a section_ir_t inside of binary_ir_t::_default_sections
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
	// using _Entry_type = std::conditional<Addr_width == address_width::x86, DWORD, ULONGLONG>::type;

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
template <address_width Addr_width = address_width::x64>
class import_module_t : public data_directory_ir_t
{
public:
	std::vector<import_t> entries;
	const std::string module_name;

	explicit import_module_t(std::string const& name)
		: module_name(name) {}
	import_module_t(import_module_t<Addr_width> const& to_copy)
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
	const uint64_t pointer_to_raw_data;

	const std::string export_name;
	const uint16_t ordinal;

	// This symbol is written to by
	//
	const uint32_t symbol;

	// Initializer that constructs string import.
	//
	explicit export_t(std::string const& name, uint32_t sym, uint64_t virt_addr, uint64_t raw_data_addr)
		: export_name(name),
		symbol(sym),
		ordinal(0),
		rva(virt_addr),
		pointer_to_raw_data(raw_data_addr)
	{}
	explicit export_t(uint32_t ord, uint32_t sym, uint64_t virt_addr, uint64_t raw_data_addr)
		: export_name(""),
		symbol(sym),
		ordinal(ord),
		rva(virt_addr),
		pointer_to_raw_data(raw_data_addr)
	{}
	export_t(export_t const& to_copy)
		: export_name(to_copy.export_name),
		symbol(to_copy.symbol),
		ordinal(to_copy.ordinal),
		rva(to_copy.rva),
		pointer_to_raw_data(to_copy.pointer_to_raw_data)
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

	void add_ordinal_export(uint32_t ordinal, uint32_t symbol, uint64_t virt_addr, uint64_t raw_data_addr)
	{
		entries.emplace_back(ordinal, symbol, virt_addr, raw_data_addr);
	}
	void add_named_export(char* name, uint32_t symbol, uint64_t virt_addr, uint64_t raw_data_addr)
	{
		entries.emplace_back(name, symbol, virt_addr, raw_data_addr);
	}
};


template <address_width Addr_width = address_width::x64>
class binary_ir_t
{
protected:
public:
	symbol_table_t m_symbol_table;

	// Header interfaces
	//
	dos_header_rep_t m_dos_header;
	file_header_rep_t m_file_header;
	optional_header_rep_t<Addr_width> m_optional_header;

	// These are the sections header interfaces from the original binary.
	std::vector<section_header_rep_t> m_sections;

	std::vector<import_module_t<Addr_width>> m_imports;
	exports_t m_exports;




	// Pretty neat, the dbghelp.dll version ImageDirectoryEntryToDataEx is implemented the exact way i thought to implement this.
	// This returns a pointer to the section within the _default_sections list and the offset within where the directory lies.
	//
	inline std::pair<uint32_t, uint32_t> rva_to_section_and_offset(uint32_t rva)
	{
		for (uint32_t i = 0; i < m_sections.size(); i++)
		{
			uint32_t section_virt_addr = m_sections[i].get_virtual_address();

			if ((rva >= section_virt_addr && rva < section_virt_addr + m_sections[i].get_size_of_raw_data()))
			{
				return { i, rva - section_virt_addr };
			}
		}
		return { 0, 0 };
	}

	inline uint32_t section_and_offset_to_raw_data(std::pair<uint32_t, uint32_t> const& section_and_offset)
	{
		return m_sections[section_and_offset.first].get_pointer_to_raw_data() + section_and_offset.second;
	}

	template <typename Ptr_type>
	Ptr_type* section_and_offset_to_raw_data(uint8_t* image_base, std::pair<uint32_t, uint32_t> const& section_and_offset)
	{
		return reinterpret_cast<Ptr_type*>(image_base + section_and_offset_to_raw_data(section_and_offset));
	}

	std::pair<uint32_t, uint32_t> data_dir_to_section_offset(uint32_t data_dir_enum)
	{
		data_dir_interface_t data_dir = m_optional_header.get_data_directory(data_dir_enum);
		if (!data_dir.get() || !data_dir.get_size() || !data_dir.get_virtual_address())
			return { 0, 0 };

		return rva_to_section_and_offset(data_dir.get_virtual_address());
	}


public:
	binary_ir_t() {}
	~binary_ir_t() {}


	// High level decomp/recomp routines
	//
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

		bool ret = from_memory(data, file_size);

		delete[] data;
		return ret;
	}
	bool to_file(std::string const& file_path)
	{
		return false;
	}
	bool from_memory(uint8_t* image_base, uint32_t image_size)
	{
		if (image_size < sizeof image_dos_header_t)
			return false;

		m_dos_header.copy_from_data(
			image_base);
		if (m_dos_header.get_magic() != IMAGE_DOS_SIGNATURE)
			return false;

		uint8_t* new_header_addr = image_base + m_dos_header.get_lfanew();

		if (image_size < m_dos_header.get_lfanew() + sizeof image_nt_headers64_t ||
			*(uint32_t*)new_header_addr != IMAGE_NT_SIGNATURE)
			return false;

		m_file_header.copy_from_data(
			new_header_addr + sizeof uint32_t);
		m_optional_header.copy_from_data(
			new_header_addr + sizeof uint32_t + sizeof image_file_header_t);

		if ((m_optional_header.get_magic() == IMAGE_NT_OPTIONAL_HDR32_MAGIC && Addr_width != address_width::x86) ||
			(m_optional_header.get_magic() == IMAGE_NT_OPTIONAL_HDR64_MAGIC && Addr_width != address_width::x64))
			return false;


		// Enumerate all sections and copy their data.
		//
		{
			image_section_header_interface_t section_header_interface(reinterpret_cast<image_section_header_t*>(
				new_header_addr + offsetof(image_nt_headers64_t, OptionalHeader) + m_file_header.get_size_of_optional_header()));

			for (uint16_t i = 0; i < m_file_header.get_number_of_sections(); ++i)
			{
				m_sections.emplace_back(image_base, section_header_interface[i]);
			}
		}

		// Build the loaded image thing. where sections are at their real rvas
		// This will replace all of this above section nonsense
		//


		// Fill normal imports
		//
		if (m_optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).get_size())
		{
			for (image_import_descriptor_interface_t import_descriptor_interface(section_and_offset_to_raw_data<image_import_descriptor_t>(image_base, data_dir_to_section_offset(IMAGE_DIRECTORY_ENTRY_IMPORT)));
				!import_descriptor_interface.is_null(); ++import_descriptor_interface)
			{
				m_imports.emplace_back(section_and_offset_to_raw_data<char>(image_base, rva_to_section_and_offset(import_descriptor_interface.get_name())));

				for (image_thunk_data_interface_t<Addr_width> thunk_data_interface(section_and_offset_to_raw_data<thunk_data_conditional_type(Addr_width)>(image_base, rva_to_section_and_offset(import_descriptor_interface.get_first_thunk())));
					!thunk_data_interface.is_null(); ++thunk_data_interface)
				{
					uint32_t symbol_index = m_symbol_table.get_symbol_index_for_rva(
						symbol_flag::base | symbol_flag::type_import,
						static_cast<uint32_t>(reinterpret_cast<uint8_t*>(thunk_data_interface.get()) - image_base));

					if (!thunk_data_interface.is_ordinal())
					{
						image_import_by_name_t* import_name = section_and_offset_to_raw_data<image_import_by_name_t>(
							image_base,
							rva_to_section_and_offset(
								thunk_data_interface.get_address_of_data()));

						m_imports.back().add_named_import(
							import_name->Hint,
							import_name->Name,
							symbol_index);
					}
					else
					{
						m_imports.back().add_ordinal_import(
							thunk_data_interface.get_masked_ordinal(),
							symbol_index);
					}
				}
			}
		}

		if (m_optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).get_size())
		{
			std::printf("Found delay load data dir.\n");
		}

		if (m_optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT).get_size())
		{
			std::printf("Found bound data dir.\n");
		}

		if (m_optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT).get_size())
		{
			image_export_directory_interface_t export_dir(section_and_offset_to_raw_data<image_export_dir_t>(image_base, data_dir_to_section_offset(IMAGE_DIRECTORY_ENTRY_EXPORT)));

			uint32_t* name_address_table = section_and_offset_to_raw_data<uint32_t>(image_base, rva_to_section_and_offset(export_dir.get_address_of_names()));
			uint32_t* export_address_table = section_and_offset_to_raw_data<uint32_t>(image_base, rva_to_section_and_offset(export_dir.get_address_of_functions()));
			uint16_t* name_ordinal_table = section_and_offset_to_raw_data<uint16_t>(image_base, rva_to_section_and_offset(export_dir.get_address_of_name_ordinals()));

			std::set<uint16_t> ordinals;
			for (uint32_t i = 0; i < export_dir.get_number_of_functions(); ++i)
				ordinals.emplace_hint(ordinals.end(), i);

			for (uint32_t i = 0; i < export_dir.get_number_of_names(); i++)
			{
				char* name = section_and_offset_to_raw_data<char>(image_base, rva_to_section_and_offset(name_address_table[i]));
				uint16_t name_ordinal = name_ordinal_table[i];

				uint32_t pointer_to_raw_data = section_and_offset_to_raw_data(
					rva_to_section_and_offset(
						export_address_table[name_ordinal]
					)
				);

				m_exports.add_named_export(name,
					m_symbol_table.get_symbol_index_for_rva(
						symbol_flag::base | symbol_flag::type_export,
						pointer_to_raw_data
					),
					export_address_table[name_ordinal],
					pointer_to_raw_data
				);

				ordinals.erase(name_ordinal);
			}

			for (uint16_t ordinal : ordinals)
			{
				uint32_t pointer_to_raw_data = section_and_offset_to_raw_data(
					rva_to_section_and_offset(
						export_address_table[ordinal]
					)
				);

				m_exports.add_ordinal_export(ordinal,
					m_symbol_table.get_symbol_index_for_rva(
						symbol_flag::base | symbol_flag::type_export,
						pointer_to_raw_data
					),
					export_address_table[ordinal],
					pointer_to_raw_data
				);
			}
		}



		// Find the code section(s)
		//


		//auto [code_section_idx, code_addr_in_section] = rva_to_section_and_offset(m_optional_header.get_base_of_code());
		//uint8_t* base_of_code_addr = section_and_offset_to_raw_data<uint8_t>(image_base, { code_section_idx, code_addr_in_section });



		return true;
	}
	bool to_memory(uint8_t* image_base, uint32_t data_size)
	{
		return false;
	}

	uint32_t get_offset_of_entry_point()
	{
		return section_and_offset_to_raw_data(rva_to_section_and_offset(m_optional_header.get_address_of_entry_point()));
	}

	// Functionality to expose the various interfaces
	//
	// dos_header_interface_t* dos_header() { return &_dos_header;  }
	// file_header_interface_t* file_header() { return &_file_header; }
	// optional_header_interface_t<Addr_width>* optional_header() { return &_optional_header; }


	inline static address_width deduce_address_width(std::string const& file_path)
	{
		if (!std::filesystem::exists(file_path))
			return address_width::invalid;

		std::ifstream file(file_path, std::ios::binary);
		if (!file.good())
			return address_width::invalid;

		file.seekg(0, std::ios::end);
		uint32_t file_size = static_cast<uint32_t>(file.tellg());
		file.seekg(0, std::ios::beg);
		uint8_t* data = new uint8_t[file_size];
		if (!data)
		{
			file.close();
			return address_width::invalid;
		}

		file.read((PCHAR)data, file_size);
		file.close();

		address_width width = deduce_address_width(data, file_size);

		delete[] data;
		return width;
	}
	inline static address_width deduce_address_width(uint8_t* image_data, uint32_t image_size)
	{
		if (image_size < sizeof image_dos_header_t)
			return address_width::invalid;
		image_dos_header_t* dos_header = (image_dos_header_t*)image_data;
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return address_width::invalid;

		image_nt_headers32_t* nt_headers = (image_nt_headers32_t*)(image_data + dos_header->e_lfanew);

		if (image_size < dos_header->e_lfanew + sizeof image_nt_headers32_t ||
			nt_headers->Signature != IMAGE_NT_SIGNATURE)
			return address_width::invalid;

		if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			return address_width::x86;
		else if (nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return address_width::x64;

		return address_width::invalid;
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
