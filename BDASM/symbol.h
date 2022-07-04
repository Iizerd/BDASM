#pragma once

#include <cstdint>
#include <map>
#include <vector>
#include <mutex>

#include "traits.h"

namespace bin_data_flag
{
	typedef uint64_t type;
	constexpr type none = 0;

	constexpr type base = (1 << 0);

	// This symbol was placed and given an updated rva
	//
	constexpr type placed = (1 << 1);


	// Sections where things are found are marked like this...
	//
	constexpr type data = (1 << 2);
	constexpr type executable = (1 << 3);


	constexpr type function_start = (1 << 4);

	constexpr type is_export = (1 << 5);


	constexpr type reloc = (1 << 6);
	constexpr type reloc_type_shift = 7;
	constexpr type reloc_type_mask = (0xF << reloc_type_shift);

	constexpr type func_data = (1 << 12);
	constexpr type func_data_shift = 13;
	constexpr type func_data_mask = (0xFFFF << func_data_shift); //imposes upper limit on function count of 2^16

	constexpr type mask = 0xffffffffffffffff;
};

// These symbols are basically an intermediate between two things. For example an instruction and another isntruction
// One instruction sets the rva once its placed in its final destination, and the other reads the rva to calculate a needed delta 
//
class bin_data_t
{
public:

	// Some rva that represents where the symbol isa. Set once its placed.
	//
	uint64_t address;

	// 
	//
	bin_data_flag::type flags;

	explicit bin_data_t(bin_data_flag::type flags = 0, uint64_t raw_address = 0)
		: flags(flags), address(raw_address) {}

	explicit bin_data_t(bin_data_t const& to_copy)
		: flags(to_copy.flags), address(to_copy.address) {}

	finline bin_data_t& set_flag(bin_data_flag::type value)
	{
		flags |= value;
		return *this;
	}
	finline bin_data_t& remove_flag(bin_data_flag::type value)
	{
		flags &= ~value;
		return *this;
	}
	finline bin_data_t& set_flag_abs(bin_data_flag::type new_flags)
	{
		flags = new_flags;
		return *this;
	}
	finline bin_data_t& set_address(uint64_t new_addr)
	{
		address = new_addr;
		return *this;
	}
	finline bin_data_t& set_flag_and_address(bin_data_flag::type flag, uint64_t addr)
	{
		//flags |= flag;
		address = addr;
		return *this;
	}
	finline void mark_as_reloc(uint8_t reloc_type)
	{
		flags |= bin_data_flag::reloc;
		flags = ((flags & ~bin_data_flag::reloc_type_mask) | (static_cast<bin_data_flag::type>(reloc_type & 0xF) << bin_data_flag::reloc_type_shift));
	}
	finline uint8_t get_reloc_type()
	{
		return ((flags & bin_data_flag::reloc_type_mask) >> bin_data_flag::reloc_type_shift);
	}

	// Accessing function data
	//
	finline bool has_func_data()
	{
		return (flags & bin_data_flag::func_data);
	}
	finline uint16_t get_func_data_idx()
	{
		return ((flags & bin_data_flag::func_data_mask) >> bin_data_flag::func_data_shift);
	}
	finline void set_func_data_idx(uint16_t idx)
	{
		flags = ((flags & ~bin_data_flag::func_data_mask) | (static_cast<bin_data_flag::type>(idx) << bin_data_flag::func_data_shift));
	}
};

struct func_sym_data_t
{
	uint32_t runtime_function_rva;
	func_sym_data_t(uint32_t rva)
		: runtime_function_rva(rva)
	{}
	func_sym_data_t(func_sym_data_t const& to_copy)
		: runtime_function_rva(to_copy.runtime_function_rva)
	{}
};

class bin_data_table_t
{
	uint32_t m_image_size;

	bin_data_t* m_image_table;

	inline constexpr static uint32_t m_arbitrary_table_idx_offset = 0xFF000000;
	std::vector<bin_data_t> m_arbitrary_table;

	std::vector<func_sym_data_t> m_func_data;

	// This is ONLY needed when allocating in the arbitrary_table 
	// So now the multi threads can access the image table without locking
	//
	std::mutex m_lock;
public:

	bin_data_table_t(uint32_t image_size, uint32_t arbitrary_table_start_size = 1000)
		: m_image_size(image_size)
	{
		m_image_table = new bin_data_t[image_size];
		for (uint32_t i = 0; i < image_size; i++)
			m_image_table[i].set_address(i);

		m_arbitrary_table.reserve(arbitrary_table_start_size);
	}
	~bin_data_table_t()
	{
		delete[] m_image_table;
	}

	void resize_image_table(uint32_t new_image_size)
	{
		bin_data_t* new_image_table = new bin_data_t[new_image_size];
		uint32_t copy_size = new_image_size;
		if (m_image_size < new_image_size)
			copy_size = m_image_size;

		for (uint32_t i = 0; i < copy_size; i++)
			new_image_table[i] = m_image_table[i];

		// Only the new stuff gets updated with rvas.
		// 
		for (uint32_t i = m_image_size; i < new_image_size; i++)
			new_image_table[i].set_address(i);

		delete[] m_image_table;
		m_image_table = new_image_table;
		m_image_size = new_image_size;
	}

	ndiscard uint32_t get_symbol_index_for_rva(uint64_t address, bin_data_flag::type flags = bin_data_flag::none)
	{
		if (address < m_arbitrary_table_idx_offset)
		{
			// So this is pretty useless atm... However to maintain the interface in case I change
			// it in the future, its staying for now.
			//
			m_image_table[address].set_flag_and_address(flags, address);
			return address;
		}
		else
		{
			return get_arbitrary_symbol_index(flags);
		}
	}

	// For symbols created after the fact, these are put in the arbitrary vector because
	// they are not within the original binary. => dont have an rva.
	//
	ndiscard uint32_t get_arbitrary_symbol_index(bin_data_flag::type flags = bin_data_flag::none)
	{
		std::lock_guard g(m_lock);
		m_arbitrary_table.emplace_back(flags, 0);
		return m_arbitrary_table_idx_offset + (static_cast<uint32_t>(m_arbitrary_table.size()) - 1);
	}

	// Access any symbol, arbitrary or not.
	//
	ndiscard finline bin_data_t& get_symbol(uint32_t symbol_index)
	{
		if (symbol_index < m_arbitrary_table_idx_offset)
			return m_image_table[symbol_index];
		else
			return m_arbitrary_table[symbol_index - m_arbitrary_table_idx_offset];
	}

	// Set placement of something and that it is valid.
	//
	finline void set_symbol_addr(uint32_t symbol_index, uint64_t address)
	{
		if (symbol_index < m_arbitrary_table_idx_offset)
			m_image_table[symbol_index].set_flag_and_address(bin_data_flag::placed, address);
		else
			m_arbitrary_table[symbol_index - m_arbitrary_table_idx_offset].set_flag(bin_data_flag::placed).set_address(address);
	}

	finline bool is_executable(uint32_t symbol_index)
	{
		if (symbol_index < m_arbitrary_table_idx_offset)
			return (m_image_table[symbol_index].flags & bin_data_flag::executable);
		else
			return (m_arbitrary_table[symbol_index - m_arbitrary_table_idx_offset].flags & bin_data_flag::executable);
	}

	finline bool inst_uses_reloc(uint32_t inst_rva, uint32_t inst_len, uint8_t& offset, uint8_t& type)
	{
		for (uint32_t i = inst_rva; i < inst_rva + inst_len; ++i)
			if (m_image_table[i].flags & bin_data_flag::reloc)
			{
				type = m_image_table[i].get_reloc_type();
				offset = i;
				return true;
			}
		return false;
	}

	finline bool has_func_data(uint32_t inst_rva)
	{
		return m_image_table[inst_rva].flags & bin_data_flag::func_data;
	}

	finline func_sym_data_t& get_func_data(uint32_t inst_rva)
	{
		return m_func_data[m_image_table[inst_rva].get_func_data_idx()];
	}

	finline void set_func_data_and_start(uint32_t inst_rva, uint32_t runtime_func_rva)
	{
		auto& sym = m_image_table[inst_rva];
		sym.flags |= bin_data_flag::function_start;
		if (sym.flags & bin_data_flag::func_data)
		{
			m_func_data[sym.get_func_data_idx()] = { runtime_func_rva };
		}
		else
		{
			auto idx = m_func_data.size();
			m_func_data.emplace_back(runtime_func_rva);
			sym.set_func_data_idx(idx);
			sym.set_flag(bin_data_flag::func_data);
		}
	}


	void unsafe_mark_range_as(uint32_t start, uint32_t size, bin_data_flag::type flag)
	{
		uint32_t end = start + size;
		for (uint32_t i = start; i < end; i++)
			m_image_table[i].flags |= flag;
	}


	// If we are in the binary itself then these are always valid so no need for more time with if
	//
	ndiscard finline uint32_t unsafe_get_symbol_index_for_rva(uint64_t address, bin_data_flag::type flags = bin_data_flag::none)
	{
		m_image_table[address].set_flag_and_address(flags, address);
		return address;
	}

	// Access symbols within the binary bounds without a check to make sure
	//
	ndiscard finline bin_data_t& unsafe_get_symbol_for_rva(uint32_t symbol_index)
	{
		return m_image_table[symbol_index];
	}


};