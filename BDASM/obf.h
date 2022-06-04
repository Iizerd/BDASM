#pragma once


#include "addr_width.h"
#include "pex.h"
#include "dasm.h"
#include "marker.h"
#include "emu.h"
#include "gen.h"




template<address_width Addr_width = address_width::x64>
class obf_routine_t
{
public:
	inst_routine_t<Addr_width>& routine;
	
};

template<address_width Addr_width = address_width::x64>
class binary_obfuscator_t
{
	binary_ir_t<Addr_width>* m_binary;
	dasm_t<Addr_width>* m_dasm;
	decoder_context_t* m_decoder_context;
	std::vector<inst_routine_t<Addr_width>*> m_marked_routines;
public:
	bool force_merge_marked_function_blocks = false;

	binary_obfuscator_t()
		:m_dasm(nullptr), m_decoder_context(nullptr)
	{
		m_binary = new binary_ir_t<Addr_width>();
	}
	~binary_obfuscator_t()
	{
		if (m_dasm)
			delete m_dasm;
		if (m_decoder_context)
			delete m_decoder_context;
		delete m_binary;
	}

	bool load_file(std::string const file_path)
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

		m_decoder_context = new decoder_context_t(m_binary->mapped_image,
			m_binary->optional_header.get_size_of_image(),
			&m_binary->symbol_table,
			&m_binary->symbol_lock,
			nullptr,
			m_binary->optional_header.get_image_base());
		m_dasm = new dasm_t<Addr_width>(m_decoder_context);

		m_dasm->is_executable = std::bind(&binary_ir_t<address_width::x64>::is_rva_in_executable_section, m_binary, std::placeholders::_1);

		m_dasm->add_routine(m_binary->optional_header.get_address_of_entry_point());

		m_dasm->run();

		m_dasm->wait_for_completion();
	}

	uint32_t enumerate_marked_functions()
	{
		for (auto& routine : m_dasm->completed_routines)
		{
			for (auto& block : routine.blocks)
			{
				if (find_begin_marker(block.instructions) != block.instructions.end())
				{
					if (!(routine.blocks.size() > 1 && !force_merge_marked_function_blocks))
					{
						routine.force_merge_blocks();
						m_marked_routines.emplace_back(&routine);
						printf("Found Marked Routine.\n");
					}
				}
			}
		}
	}

	void do_it()
	{
		for (auto routine : m_marked_routines)
		{

		}
	}

	void export_marked_routine_and_nop_marker(std::string const& dir_path)
	{
		for (auto routine : m_marked_routines)
		{
			auto begin_start = find_begin_marker(routine->blocks.front().instructions);
			if (begin_start == routine->blocks.front().instructions.end())
				continue;

			auto [attributes, marker_id] = get_begin_data(begin_start);

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

			uint64_t marker_offset = m_binary->symbol_table.get_symbol(begin_start->my_symbol).address - routine->start;
			uint8_t* routine_buffer = new uint8_t[routine_size];
			std::memcpy(routine_buffer, m_binary->mapped_image + routine->start, routine_size);
			std::memset(routine_buffer + marker_offset, 0x90, 9);

			file.write(reinterpret_cast<char*>(routine_buffer), routine_size);
			file.close();
		}
	}
};

