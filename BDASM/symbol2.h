//#pragma once
//
//#include <cstdint>
//#include <vector>
//#include <map>
//
//#include "traits.h"
//
//
//namespace symbol_flag
//{
//	typedef uint32_t type;
//	type none = 0;
//
//	// Indicates that the address is relative to
//	// These are used to key into the map and find symbols.
//	// After that they dont matter.
//	//
//	type base = (1 << 0);
//
//	// import_lookup_key uses this to mask to only the values used in the key.
//	//
//	type key_mask = (1 << 0);
//
//
//	// An instruction or other isntrument set this symbol after final placement and the address is valid.
//	// If this isn't set upon recompilation... something is very wrong.
//	//
//	type valid = (1 << 1);
//
//
//	// The type descriptor for debug purposes i think...
//	// Will probably remove this later
//	//
//	type type_export = (1 << 2);
//	type type_import = (1 << 3);
//
//
//	type mask = 0xffffffff;
//};
//
//// These symbols are basically an intermediate between two things. For example an instruction and another isntruction
//// One instruction sets the rva once its placed in its final destination, and the other reads the rva to calculate a needed delta 
////
//class intern_symbol_t
//{
//public:
//
//	// Some rva that represents where the symbol is. Set once its placed.
//	//
//	uint64_t rva;
//
//	// 
//	//
//	uint32_t flags;
//
//	explicit intern_symbol_t(uint32_t symbol_flags, uint64_t raw_address)
//		: flags(symbol_flags), rva(raw_address) {}
//
//	explicit intern_symbol_t(intern_symbol_t const& to_copy)
//		: flags(to_copy.flags), rva(to_copy.rva) {}
//};
//
//typedef uint32_t* symbol_t;
//
//#define make_symbol_map_key(macro_flag, macro_addr)														\
//static_cast<uint64_t>(																					\
//	(																									\
//		((static_cast<uint64_t>(macro_flag) & static_cast<uint64_t>(symbol_flag::key_mask)) << 32)		\
//		|																								\
//		static_cast<uint64_t>(macro_addr & 0xffffffff)													\
//		)																								\
//	)
//
//
//class symbol_table_t
//{
//	// An array of uint32_ts allocated on the heap, which indices into m_entries;
//	//
//	std::vector<symbol_t> m_symbol_handles;
//
//	// The actual symbols
//	//
//	std::vector<intern_symbol_t> m_entries;
//
//	// A map to aid in looking up previously used symbols.
//	//
//	std::map<uint64_t, symbol_t> m_lookup_table;
//
//public:
//	explicit symbol_table_t(uint32_t base_table_size = 3000)
//	{
//		m_entries.reserve(base_table_size);
//	}
//	explicit symbol_table_t(symbol_table_t const& table)
//	{
//		m_entries.insert(m_entries.begin(), table.m_entries.begin(), table.m_entries.end());
//		m_lookup_table.insert(table.m_lookup_table.begin(), table.m_lookup_table.end());
//	}
//
//	[[nodiscard]] symbol_t get_symbol_for_rva(symbol_flag::type flags, uint64_t address)
//	{
//		uint64_t map_key = make_symbol_map_key(flags, address);
//		auto it = m_lookup_table.find(map_key);
//		if (it == m_lookup_table.end())
//		{
//			uint32_t index = static_cast<uint32_t>(m_entries.size());
//			m_entries.emplace_back(flags, address);
//			symbol_t sym = new uint32_t;
//			*sym = index;
//			m_lookup_table[map_key] = sym;
//			return sym;
//		}
//		return it->second;
//	}
//
//	[[nodiscard]] symbol_t get_arbitrary_symbol(symbol_flag::type flags = symbol_flag::none)
//	{
//		m_entries.emplace_back(flags, 0);
//		symbol_t sym = new uint32_t;
//		*sym = static_cast<uint32_t>(m_entries.size() - 1);
//		return sym;
//	}
//
//	[[nodiscard]] finline intern_symbol_t& symbol(symbol_t sym)
//	{
//		return m_entries[*sym];
//	}
//
//	finline void set_sym_addr_and_valid(symbol_t sym, uint64_t address)
//	{
//		uint32_t idx = *sym;
//		m_entries[idx].rva = address;
//		m_entries[idx].flags |= symbol_flag::valid;
//	}
//
//	void merge(symbol_table_t& table)
//	{
//		for (auto const& sym : m_lookup_table)
//		{
//			
//		}
//	}
//};
//
//
