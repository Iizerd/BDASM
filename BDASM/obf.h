#pragma once


#include "addr_width.h"
#include "pex.h"
#include "dasm.h"
#include "marker.h"
#include "emu.h"
#include "gen.h"


namespace obf
{

	template<dasm::address_width Addr_width = dasm::address_width::x64>
	class obf_routine_t
	{
	public:
		dasm::inst_routine_t<Addr_width>& routine;

	};

	template<dasm::address_width Addr_width = dasm::address_width::x64, uint8_t Thread_count = 1>
	class binary_obfuscator_t
	{
		pex::binary_ir_t<Addr_width>* m_binary;
	public:
		dasm::dasm_t<Addr_width, Thread_count>* m_dasm;
	private:
		dasm::decoder_context_t* m_decoder_context;
		std::vector<dasm::inst_routine_t<Addr_width>*> m_marked_routines;
	public:
		bool force_merge_marked_function_blocks = false;

		binary_obfuscator_t()
			:m_dasm(nullptr), m_decoder_context(nullptr)
		{
			m_binary = new pex::binary_ir_t<Addr_width>();
		}
		~binary_obfuscator_t()
		{
			if (m_dasm)
				delete m_dasm;
			if (m_decoder_context)
				delete m_decoder_context;
			delete m_binary;
		}

		bool load_file(std::string const& file_path)
		{
			std::ifstream file(file_path, std::ios::binary);
			if (!file.good())
				return false;

			file.seekg(0, std::ios::end);
			size_t file_length = file.tellg();
			file.seekg(0, std::ios::beg);
			uint8_t* file_buffer = (uint8_t*)malloc(file_length);
			if (!file_buffer)
				return false;
			file.read((PCHAR)file_buffer, file_length);
			file.close();

			if (!m_binary->map_image(file_buffer, file_length))
				return false;

			m_decoder_context = new dasm::decoder_context_t(m_binary->mapped_image,
				m_binary->optional_header.get_size_of_image(),
				m_binary->symbol_table,
				nullptr,
				m_binary->optional_header.get_image_base()
			);

			m_decoder_context->settings.recurse_calls = true;

			m_dasm = new dasm::dasm_t<Addr_width, Thread_count>(m_decoder_context);

			m_dasm->is_executable = std::bind(&pex::binary_ir_t<dasm::address_width::x64>::is_rva_in_executable_section, m_binary, std::placeholders::_1);

			//m_dasm->add_routine(m_binary->optional_header.get_address_of_entry_point());

			uint32_t count = 0;
			auto addr = m_binary->mapped_image + m_binary->optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).get_virtual_address();
			for (pex::image_runtime_function_it_t m_runtime_functions(reinterpret_cast<pex::image_runtime_function_entry_t*>(addr));
			!m_runtime_functions.is_null(); ++m_runtime_functions)
			{
				if (m_binary->is_rva_in_executable_section(m_runtime_functions.get_begin_address()))
					m_dasm->add_routine(m_runtime_functions.get_begin_address());
				count++;
			}
			//std::printf("This many count runtime: %u\n", count);


			/*m_binary->enum_base_relocs([](uint8_t* base, pex::image_base_reloc_block_it_t block, pex::image_base_reloc_it_t it, uint32_t num)
				{
					for (uint32_t i = 0; i < block.get_num_of_relocs(); i++)
						std::printf("Reloc %p %p %016X, %X, %u, %s\n", block.get(), it[i].get(), block.get_virtual_address() + it[i].get_offset(), it[i].get_offset(), it[i].get_type(), it[i].get_type_name().data());
					return true;
				});*/

			m_dasm->run();

			m_dasm->wait_for_completion();
		}

		bool save_file(std::string const& file_path)
		{
			uint32_t data_size = 0;
			auto data = m_binary->unmap_image(data_size);

			std::ofstream file(file_path, std::ios::binary);
			file.write((char*)data, data_size);
			file.close();
			return true;
		}

		uint32_t enumerate_marked_functions()
		{
			for (auto& routine : m_dasm->completed_routines)
			{
				for (auto& block : routine.blocks)
				{
					if (auto begin_marker_start = find_begin_marker(block.instructions); begin_marker_start != block.instructions.end())
					{
						if (!(routine.blocks.size() > 1 && !force_merge_marked_function_blocks))
						{
							routine.force_merge_blocks();
							m_marked_routines.emplace_back(&routine);

							auto begin_marker_end = begin_marker_start;
							std::advance(begin_marker_end, __BDASM_BEGIN_INST_COUNT);

							block.instructions.erase(begin_marker_start, begin_marker_end);

							printf("Found Marked Routine.\n");
						}
					}
				}
			}
			return 1;
		}

		void do_it()
		{
			for (auto routine : m_marked_routines)
			{
				auto rva = m_binary->append_section(".TEST", routine->blocks.front().get_size(), 0, true);
				routine->blocks.front().place_at(rva, m_binary->symbol_table);
				routine->blocks.front().encode_to(m_binary->mapped_image + rva, rva, m_binary->symbol_table);
			}
		}


		void export_marked_routine_and_nop_marker(std::string const& dir_path)
		{
			printf("trying to export %llu\n", m_marked_routines.size());
			for (auto routine : m_marked_routines)
			{
				routine->blocks.front().print_block();
				printf("Exporting. %llu\n", routine->blocks.size());

				auto begin_start = find_begin_marker(routine->blocks.front().instructions);
				if (begin_start == routine->blocks.front().instructions.end())
					continue;

				auto [attributes, marker_id] = get_begin_data(begin_start);

				std::printf(" %X %X data.\n", attributes, marker_id);

				uint64_t routine_size = routine->end - routine->start;
				std::string file_path = dir_path;
				file_path.append("sub_")
					.append(std::to_string(routine->start))
					.append("_")
					.append(std::to_string(routine_size))
					.append("_")
					.append(std::to_string(marker_id));

				std::ofstream file(file_path, std::ios::binary);
				if (!file.good())
					continue;

				uint64_t marker_offset = m_binary->symbol_table->get_symbol(begin_start->my_symbol).address - routine->start;
				uint8_t* routine_buffer = new uint8_t[routine_size];
				std::memcpy(routine_buffer, m_binary->mapped_image + routine->start, routine_size);
				std::memset(routine_buffer + marker_offset, 0x90, 9);

				file.write(reinterpret_cast<char*>(routine_buffer), routine_size);
				file.close();
			}
		}
	};

}
