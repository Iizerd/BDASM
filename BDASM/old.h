

//Import parser
			/*for (image_import_descriptor_it_t import_descriptor_interface(section_and_offset_to_raw_data<image_import_descriptor_t>(m_raw_data, data_dir_to_section_offset(IMAGE_DIRECTORY_ENTRY_IMPORT)));
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
			}*/




