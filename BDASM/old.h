
// Old functions to deal with the image when its in raw data form
// Turns out its much better to map it into memory as if it were to be executed
//
/*
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

	template<typename Ptr_type>
	Ptr_type* section_and_offset_to_raw_data(uint8_t* image_base, std::pair<uint32_t, uint32_t> const& section_and_offset)
	{
		return reinterpret_cast<Ptr_type*>(image_base + section_and_offset_to_raw_data(section_and_offset));
	}

	std::pair<uint32_t, uint32_t> data_dir_to_section_offset(uint32_t data_dir_enum)
	{
		data_dir_it_t data_dir = m_optional_header.get_data_directory(data_dir_enum);
		if (!data_dir.get() || !data_dir.get_size() || !data_dir.get_virtual_address())
			return { 0, 0 };

		return rva_to_section_and_offset(data_dir.get_virtual_address());
	}

*/


//Import parser
//
/*
for (image_import_descriptor_it_t import_descriptor_interface(section_and_offset_to_raw_data<image_import_descriptor_t>(m_raw_data, data_dir_to_section_offset(IMAGE_DIRECTORY_ENTRY_IMPORT)));
	!import_descriptor_interface.is_null(); ++import_descriptor_interface)
{
	m_imports.emplace_back(section_and_offset_to_raw_data<char>(m_raw_data, rva_to_section_and_offset(import_descriptor_interface.get_name())));

	for (image_thunk_data_it_t<Addr_width> thunk_data_interface(section_and_offset_to_raw_data<thunk_data_conditional_type(Addr_width)>(m_raw_data, rva_to_section_and_offset(import_descriptor_interface.get_first_thunk())));
		!thunk_data_interface.is_null(); ++thunk_data_interface)
	{
		uint32_t symbol_index = m_symbol_table.get_symbol_index_for_rva(
			symbol_flag::base | symbol_flag::type_import,
			static_cast<uint32_t>(reinterpret_cast<uint8_t*>(thunk_data_interface.get()) - m_raw_data));

		if (!thunk_data_interface.is_ordinal())
		{
			image_import_by_name_t* import_name = section_and_offset_to_raw_data<image_import_by_name_t>(
				m_raw_data,
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
*/




