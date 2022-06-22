#pragma once

#include "addr_width.h"
#include "pex.h"
#include "dasm.h"
#include "marker.h"
#include "emu.h"
#include "gen.h"
#include "encoder.h"
#include "align.h"



/*
	TODO: Create a tree that demonstrates what functions call what.

	Create the gadgets for absolute addressing. Data, jumps, relbrs, calls all that.
*/

namespace obf
{
	template<dasm::addr_width::type Addr_width = dasm::addr_width::x64>
	class obf_routine_t
	{
	public:
		uint64_t entry_rva;

		uint8_t has_marker;
		uint8_t m_attributes;

		dasm::inst_routine_t<Addr_width>& m_routine;

		//dasm::inst_block_t<Addr_width>& m_inst_block;

		obf_routine_t(dasm::inst_routine_t<Addr_width>& func)
			: m_routine(func)/*, m_inst_block(func.blocks.front())*/
		{ 
			if (auto marker = find_marker(m_routine.blocks.front().instructions); marker != m_routine.blocks.front().instructions.end())
			{
				/*m_attributes = get_marker_attributes(marker);
				auto maker_end = marker;
				std::advance(maker_end, BDASM_MARKER_INST_COUNT);
				m_inst_block.instructions.erase(marker, maker_end);*/
				printf("Found a marker.\n");
			}
		}

		// Because of xed dropping useless rex prefixes and messing up the size of instructions, 
		// This is needed.
		//
		void prep_for_obf_pass()
		{
			for (auto& block : m_routine.blocks)
			{
				for (auto& inst : block.instructions)
				{
					// Update all relbrs to 32bit
					auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
					if (cat == XED_CATEGORY_UNCOND_BR)
					{
						xed_decoded_inst_set_branch_displacement_bits(&inst.decoded_inst, 0, 32);
					}
					else if (cat == XED_CATEGORY_COND_BR)
					{
						switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
						{
						case XED_IFORM_JMP_RELBRb:
						case XED_IFORM_JMP_RELBRd:
						case XED_IFORM_JMP_RELBRz:
							xed_decoded_inst_set_branch_displacement_bits(&inst.decoded_inst, 0, 32);
						}
					}

					// Need to redecude all instructions because xed drops things like unused rex prefixes
					// found in the crt startup(why tf are the here??) for whatever reason
					//
					inst.redecode();
				}
			}
		}

		// Use a single traversal to place the instructions and get the size needed.
		//
		void place_and_advance(uint64_t &rva, symbol_table_t* sym_table)
		{
			for (auto& block : m_routine.blocks)
				rva = align_up(block.place_in_binary(rva, sym_table), 0x10);
		}
		
		// Second traversal to encode_to_binary the instructions where they were placed
		//
		uint8_t* encode_to_binary(pex::binary_t<Addr_width>* binary, uint8_t* dest, uint64_t& entry_rva)
		{
			for (auto& block : m_routine.blocks)
			{
				if (auto block_rva = dest - binary->mapped_image; block.start == m_routine.entry_rva)
					entry_rva = block_rva;
				dest = align_up_ptr(block.encode_to_binary(binary, dest), 0x10);
			}
			return dest;
		}
	};

	template<dasm::addr_width::type Addr_width = dasm::addr_width::x64, uint8_t Thread_count = 1>
	class binary_obfuscator_t
	{
	public:
		pex::binary_t<Addr_width>* m_binary;

		dasm::decoder_context_t<Addr_width>* m_decoder_context;

		std::list<obf_routine_t<Addr_width> > m_obf_routines;
	public:
		dasm::dasm_t<Addr_width, Thread_count>* m_dasm;

		bool force_merge_marked_function_blocks = false;

		binary_obfuscator_t()
			:m_dasm(nullptr), m_decoder_context(nullptr)
		{
			m_binary = new pex::binary_t<Addr_width>();
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

			m_decoder_context = new dasm::decoder_context_t(m_binary);

			m_decoder_context->settings.recurse_calls = true;
			m_decoder_context->settings.block_combination_threshold = 0;

			m_dasm = new dasm::dasm_t<Addr_width, Thread_count>(m_decoder_context);

			//m_dasm->is_executable = std::bind(&pex::binary_t<dasm::addr_width::x64>::is_rva_in_executable_section, m_binary, std::placeholders::_1);

			//m_dasm->add_routine(m_binary->optional_header.get_address_of_entry_point());

			uint32_t count = 0;
			auto addr = m_binary->mapped_image + m_binary->optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).get_virtual_address();
			for (pex::image_runtime_function_it_t m_runtime_functions(reinterpret_cast<pex::image_runtime_function_entry_t*>(addr));
				!m_runtime_functions.is_null(); ++m_runtime_functions)
			{
				if (m_binary->is_rva_in_executable_section(m_runtime_functions.get_begin_address()))
					m_dasm->add_routine(m_runtime_functions.get_begin_address(), m_runtime_functions.get_end_address());
				count++;
			}
			std::printf("This many count runtime: %u\n", count);

			if (auto entry = m_binary->optional_header.get_address_of_entry_point(); entry)
				m_dasm->add_routine(entry, 0);

			//printf("Entry point %X\n", m_binary->optional_header.get_address_of_entry_point());


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

		bool contains_relocations(dasm::inst_routine_t<Addr_width> const& routine)
		{
			for (auto const& reloc : m_binary->base_relocs)
			{
				if (reloc.second >= routine.start && reloc.second < routine.end)
				{
					return true;
				}
			}
			return false;
		}

		bool accepted_rva(uint64_t rva)
		{
			switch (rva)
			{
			case 0x1398:
				return true;
			}
			return false;
		}

		void enumerate_obf_functions()
		{
			for (auto& routine : m_dasm->completed_routines)
			{
				if (/*accepted_rva(routine.entry_it->start) &&*/
					routine.complete_disassembly &&
					routine.blocks.size() == 1 &&
					routine.entry_it->get_size() > 4 &&
					!contains_relocations(routine))
				{
					//std::printf("Func at %X with size %llu\n", routine.start, routine.blocks.front().get_size());
					//routine.promote_relbrs();
					m_obf_routines.emplace_back(routine).prep_for_obf_pass();
				}
			}
			printf("Found %lld functions to obfuscate.\n", m_obf_routines.size());
		}

		// Say goodbye to exception handling.
		void do_it()
		{
			// First we place them all...
			//
			uint64_t section_base = m_binary->next_section_rva();
			for (auto& routine : m_obf_routines)
			{
				routine.place_and_advance(section_base, m_binary->symbol_table);
			}

			uint64_t rva = m_binary->append_section(".TEST", section_base - m_binary->next_section_rva(), IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE, true);
			auto dest = m_binary->mapped_image + rva;
			for (auto& routine : m_obf_routines)
			{
				uint64_t entry = 0;
				dest = routine.encode_to_binary(m_binary, dest, entry);
				
				//printf("writing jump from %X to %X\n", routine.m_routine.entry_it->start, entry);

				encode_inst_in_place(m_binary->mapped_image + routine.m_routine.entry_it->start,
					dasm::addr_width::machine_state<Addr_width>::value,
					XED_ICLASS_JMP,
					32,
					xed_relbr(entry - routine.m_routine.entry_it->start - 5, 32)
				);
			}
		}


		void export_marked_routine_and_nop_marker(std::string const& dir_path)
		{
			/*printf("trying to export %llu\n", m_marked_routines.size());
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
			}*/
		}
	};

}
