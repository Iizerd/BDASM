#pragma once

#include <cstdint>
#include <map>
#include <vector>
#include <mutex>

#include "traits.h"

namespace symbol_flag
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

	constexpr type is_export = (1 << 4);

	constexpr type reloc = (1 << 5);
	constexpr type reloc_type_shift = 6;
	constexpr type reloc_type_mask = (0xF << reloc_type_shift);

	constexpr type mask = 0xffffffff;
};

class symbol_attribute_t
{
public:
	virtual void print_details()
	{
		std::printf("Default symbol attributes.\n");
	}
};

// These symbols are basically an intermediate between two things. For example an instruction and another isntruction
// One instruction sets the rva once its placed in its final destination, and the other reads the rva to calculate a needed delta 
//
class symbol_t
{
public:

	// Some rva that represents where the symbol isa. Set once its placed.
	//
	uint64_t address;

	// 
	//
	symbol_flag::type flags;

	explicit symbol_t(symbol_flag::type flags = 0, uint64_t raw_address = 0)
		: flags(flags), address(raw_address) {}

	explicit symbol_t(symbol_t const& to_copy)
		: flags(to_copy.flags), address(to_copy.address) {}

	finline symbol_t& set_flag(symbol_flag::type value)
	{
		flags |= value;
		return *this;
	}
	finline symbol_t& remove_flag(symbol_flag::type value)
	{
		flags &= ~value;
		return *this;
	}
	finline symbol_t& set_flag_abs(symbol_flag::type new_flags)
	{
		flags = new_flags;
		return *this;
	}
	finline symbol_t& set_address(uint64_t new_addr)
	{
		address = new_addr;
		return *this;
	}
	finline symbol_t& set_flag_and_address(symbol_flag::type flag, uint64_t addr)
	{
		//flags |= flag;
		address = addr;
		return *this;
	}
	finline void mark_as_reloc(uint8_t reloc_type)
	{
		flags |= symbol_flag::reloc;
		flags = ((flags & ~symbol_flag::reloc_type_mask) | ((reloc_type & 0xF) << symbol_flag::reloc_type_shift));
	}
	finline uint8_t get_reloc_type()
	{
		return ((flags & symbol_flag::reloc_type_mask) >> symbol_flag::reloc_type_shift);
	}
};

class symbol_table_t
{
	uint32_t m_image_size;

	symbol_t* m_image_table;

	inline constexpr static uint32_t m_arbitrary_table_idx_offset = 0xFFFF0000;
	std::vector<symbol_t> m_arbitrary_table;

	// This is ONLY needed when allocating in the arbitrary_table 
	// So now the multi threads can access the image table without locking
	//
	std::mutex m_lock;
public:

	symbol_table_t(uint32_t image_size, uint32_t arbitrary_table_start_size = 1000)
		: m_image_size(image_size)
	{
		m_image_table = new symbol_t[image_size];
		for (uint32_t i = 0; i < image_size; i++)
			m_image_table[i].set_address(i);

		m_arbitrary_table.reserve(arbitrary_table_start_size);
	}
	~symbol_table_t()
	{
		delete[] m_image_table;
	}

	void resize_image_table(uint32_t new_image_size)
	{
		symbol_t* new_image_table = new symbol_t[new_image_size];
		uint32_t copy_size = min(new_image_size, m_image_size);
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

	ndiscard uint32_t get_symbol_index_for_rva(uint64_t address, symbol_flag::type flags = symbol_flag::none)
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
	ndiscard uint32_t get_arbitrary_symbol_index(symbol_flag::type flags = symbol_flag::none)
	{
		std::lock_guard g(m_lock);
		m_arbitrary_table.emplace_back(flags, 0);
		return m_arbitrary_table_idx_offset + (static_cast<uint32_t>(m_arbitrary_table.size()) - 1);
	}

	// Access any symbol, arbitrary or not.
	//
	ndiscard finline symbol_t& get_symbol(uint32_t symbol_index)
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
			m_image_table[symbol_index].set_flag_and_address(symbol_flag::placed, address);
		else
			m_arbitrary_table[symbol_index - m_arbitrary_table_idx_offset].set_flag(symbol_flag::placed).set_address(address);
	}


	finline bool is_executable(uint32_t symbol_index)
	{
		if (symbol_index < m_arbitrary_table_idx_offset)
			return m_image_table[symbol_index].flags & symbol_flag::executable;
		else
			return m_arbitrary_table[symbol_index - m_arbitrary_table_idx_offset].flags & symbol_flag::executable;
	}

	finline bool inst_uses_reloc(uint32_t inst_rva, uint32_t inst_len)
	{
		for (uint32_t i = inst_rva; i < inst_rva + inst_len; ++i)
			if (m_image_table[i].flags & symbol_flag::reloc);
				return true;
		return false;
	}





	// If we are in the binary itself then these are always valid so no need for more time with if
	//
	ndiscard finline uint32_t unsafe_get_symbol_index_for_rva(uint64_t address, symbol_flag::type flags = symbol_flag::none)
	{
		m_image_table[address].set_flag_and_address(flags, address);
		return address;
	}

	// Access symbols within the binary bounds without a check to make sure
	//
	ndiscard finline symbol_t& unsafe_get_symbol_for_rva(uint32_t symbol_index)
	{
		return m_image_table[symbol_index];
	}


};