
//#define make_symbol_map_key(macro_flag, macro_addr)															\
//static_cast<uint64_t>(																						\
//		(																									\
//			((static_cast<uint64_t>(macro_flag) & static_cast<uint64_t>(symbol_flag::key_mask)) << 32)		\
//			|																								\
//			static_cast<uint64_t>(macro_addr & 0xffffffff)													\
//		)																									\
//	)
//class symbol_table_t
//{
//	// Lookup table to support lookups of static things
//	// imports, functions, rvas inside binary, anything
//	//
//	std::map<uint64_t, uint32_t> m_lookup_table;
//
//	//
//	std::vector<symbol_t> m_entries;
//
//public:
//	explicit symbol_table_t(uint32_t base_table_size = 3000)
//	{
//		m_entries.emplace_back(symbol_flag::none, 0);
//		m_entries.reserve(base_table_size);
//	}
//	explicit symbol_table_t(symbol_table_t const& table)
//	{
//		m_entries.insert(m_entries.begin(), table.m_entries.begin(), table.m_entries.end());
//		m_lookup_table.insert(table.m_lookup_table.begin(), table.m_lookup_table.end());
//	}
//
//	// For looking up symbols that are inside the original binary.
//	// Ex: auto import_sym_idx = get_symbol_index_for_rva(symbol_flag::base, import_addr);
//	//
//	ndiscard uint32_t get_symbol_index_for_rva(symbol_flag::type flags, uint64_t address)
//	{
//		uint64_t map_key = make_symbol_map_key(flags, address);
//		auto it = m_lookup_table.find(map_key);
//		if (it == m_lookup_table.end())
//		{
//			uint32_t index = static_cast<uint32_t>(m_entries.size());
//			m_entries.emplace_back(flags, address);
//			m_lookup_table[map_key] = index;
//			return index;
//		}
//		return it->second;
//	}
//
//	// For symbols created after the fact, these dont get an entry in the lookup table because
//	// they are not within the original binary. => dont have an rva.
//	//
//	ndiscard uint32_t get_arbitrary_symbol_index(symbol_flag::type flags = symbol_flag::none)
//	{
//		m_entries.emplace_back(flags, 0);
//		return static_cast<uint32_t>(m_entries.size()) - 1;
//	}
//
//	ndiscard finline symbol_t& get_symbol(uint32_t symbol_index)
//	{
//		return m_entries[symbol_index];
//	}
//	finline void set_symbol_addr(uint32_t symbol_index, uint64_t address)
//	{
//		m_entries[symbol_index].set_flag(symbol_flag::placed).set_address(address);
//		/*m_entries[symbol_index].address = address;
//		m_entries[symbol_index].flags |= symbol_flag::placed;*/
//	}
//};

