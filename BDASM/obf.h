#pragma once

#include <vector>
#include <functional>

#include "align.h"
#include "dasm.h"
#include "flags.h"

namespace obf
{
	enum class pass_status_t
	{
		// Complete and total failure that means we need to scrub the whole process
		//
		critical_failure,

		// Failure but its ok, the routine is still intact and we can proceed with other routines
		//
		failure,

		// 
		//
		success,
	};


	/*template<addr_width::type aw = addr_width::x64>
	class routine_t;*/

	template<addr_width::type aw = addr_width::x64>
	class obf_t;

	//template<addr_width::type aw = addr_width::x64>
	//struct context_t
	//{
	//	dasm::linker_t& linker;
	//	pex::binary_t<aw>& bin;
	//	std::list<routine_t<aw>>& obf_routines;
	//	std::list<dasm::routine_t<aw>>& additional_routines;
	//};

	template<addr_width::type aw = addr_width::x64>
	class routine_t
	{
	public:
		dasm::routine_t<aw>& m_routine;

		// Space the original function occupied, how much we have to place a jump
		//
		uint32_t original_space;
	public:

		routine_t(dasm::routine_t<aw>& routine, uint32_t space)
			: m_routine(routine)
			, original_space(space)
		{}

		template<typename Pass_type, typename... Params>
		pass_status_t mutation_pass(obf_t<aw>& ctx, Params... params)
		{
			return Pass_type::pass(m_routine, ctx, params...);
		}
	};

	namespace data_flag
	{
		typedef uint32_t type;
		constexpr type none = 0;

		// data = rva(link1)
		constexpr type rva_32 = (1 << 0);
		constexpr type rva_64 = (1 << 1);

		// data = rva(link2) - rva(link1)
		constexpr type disp_32 = (1 << 3);


	}

	template<addr_width::type aw = addr_width::x64>
	class data_chunk_t
	{
		std::vector<std::tuple<uint32_t, data_flag::type, uint32_t, uint32_t>> patches;

		std::vector<std::tuple<uint32_t, uint32_t>> links;
	public:
		std::vector<uint8_t> raw_data;
		
		void add_patch(uint32_t offset, data_flag::type flags, uint32_t link1, uint32_t link2)
		{
			patches.emplace_back(offset, flags, link1, link2);
		}

		void add_link(uint32_t link, uint32_t offset)
		{
			links.emplace_back(link, offset);
		}

		// For the placement pass
		//
		void place_in_binary(dasm::linker_t* linker, uint64_t& rva)
		{
			for (auto [link, offset] : links)
			{
				linker->set_link_addr(link, rva + offset);
			}
			rva += raw_data.size():
		}

		// For the encode/write pass. using memcpy because of possible unaligned writes
		//
		void write_to_binary(uint8_t* data, dasm::linker_t* linker)
		{
			for (auto [offset, flags, link1, link2] : patches)
			{
				if (flags & data_flag::rva_32)
				{
					uint32_t rva = linker->get_link_addr(link1);
					std::memcpy(data + offset, &rva, sizeof uint32_t);
				}
				else if (flags & data_flag::rva_64)
				{
					uint64_t rva = linker->get_link_addr(link1);
					std::memcpy(data + offset, &rva, sizeof uint64_t);
				}
				else if (flags & data_flag::disp_32)
				{
					int64_t dest = linker->get_link_addr(link2);
					int64_t source = linker->get_link_addr(link1);
					int32_t disp = dest - source;
					std::memcpy(data + offset, &disp, sizeof(int32_t));
				}
			}
		}
	};

	//https://www.youtube.com/watch?v=pXwbj_ZPKwg&ab_channel=VvporTV
	//
	template<addr_width::type aw>
	class obf_t
	{
		std::vector<std::function<pass_status_t(dasm::routine_t<aw>&, obf_t<aw>&)>> single_passes;

		dasm::decoder_context_t<aw>* m_decoder_context;

		uint32_t func_alignment;

		uint32_t block_alignment;
	public:
		dasm::linker_t* linker;

		dasm::dasm_t<aw, 1>* dasm;

		pex::binary_t<aw>* bin;

		std::list<routine_t<aw>> obf_routines;

		std::list<data_chunk_t<aw>> data_chunks;

		// These are routines that are added after the fact and we dont want to apply obfuscation passes to.
		//
		std::list<dasm::routine_t<aw>> additional_routines;

		obf_t()
			: dasm(nullptr)
			, m_decoder_context(nullptr)
			, linker(nullptr)
			, bin(new pex::binary_t<aw>)
			, func_alignment(1)
			, block_alignment(1)
		{}

		~obf_t()
		{
			if (dasm)
				delete dasm;
			if (m_decoder_context)
				delete m_decoder_context;
			if (linker)
				delete linker;

			delete bin;
		}


		bool set_func_alignment(uint32_t new_alignment)
		{
			if (func_alignment == 1)
			{
				func_alignment = new_alignment;
				return true;
			}
			return false;
		}

		bool set_block_alignment(uint32_t new_alignment)
		{
			if (block_alignment == 1)
			{
				block_alignment = new_alignment;
				return true;
			}
			return false;
		}

		bool routine_analysis(dasm::routine_t<aw>& routine, uint32_t& start_size)
		{
			uint32_t start = routine.entry_block->rva_start;
			uint32_t end = routine.entry_block->rva_end;
			start_size = end - start;

			std::vector<dasm::block_t<aw>*> blocks;
			for (auto& block : routine.blocks)
				blocks.emplace_back(&block);

			for (uint32_t i = 0; i < blocks.size();)
			{
				if (blocks[i]->termination_type == dasm::termination_type_t::invalid)
				{
					printf("Invalid block at [%X:%X]\n", blocks[i]->rva_start, blocks[i]->rva_end);
					return false;
				}
				if (blocks[i]->rva_start == end)
				{
					end = blocks[i]->rva_end;
					std::swap(blocks[i], blocks[blocks.size() - 1]);
					blocks.pop_back();
					i = 0;
				}
				else
					++i;
			}

			start_size = end - start;

			return true;
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

			if (!bin->map_image(file_buffer, file_length))
				return false;

			linker = new dasm::linker_t(bin->optional_header.get_size_of_image(), 0x10000);

			m_decoder_context = new dasm::decoder_context_t(bin);
			m_decoder_context->settings.recurse_calls = true;
			m_decoder_context->linker = linker;

			dasm = new dasm::dasm_t<aw, 1>(m_decoder_context);

			// First we add all runtime func as possible entries
			//
			/*auto addr = bin->mapped_image + bin->optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).get_virtual_address();
			for (pex::image_runtime_function_it_t m_runtime_functions(reinterpret_cast<pex::image_runtime_function_entry_t*>(addr));
				!m_runtime_functions.is_null(); ++m_runtime_functions)
			{
				dasm->add_routine(m_runtime_functions.get_begin_address());
			}*/


			// Add all exports, which we are SURE make functions
			//
			for (auto& exprt : bin->m_exports.entries)
			{
				dasm->add_routine(exprt.rva, true);
			}

			// Finally we add the entry point
			//
			if (auto entry = bin->optional_header.get_address_of_entry_point(); entry)
				dasm->add_routine(entry, true);


			dasm->run();

			dasm->wait_for_completion();

			for (auto& routine : dasm->completed_routines)
			{
				if (uint32_t size = 0; routine_analysis(routine, size) && size > 5)
				{
					routine.promote_relbrs();
					obf_routines.emplace_back(routine, size);
				}
			}
		}

		void save_file(std::string const& file_path)
		{
			uint32_t data_size = 0;
			auto data = bin->unmap_image(data_size);

			std::ofstream file(file_path, std::ios::binary);
			file.write(reinterpret_cast<char*>(data), data_size);
			file.close();
		}


		template<typename Pass_type, typename... Params>
		pass_status_t group_pass(Params... params)
		{
			return Pass_type::pass(*this, params...);
		}

		template<typename Pass_type, typename... Params>
		void register_single_pass(Params... params)
		{
			single_passes.push_back(std::bind(&Pass_type::template pass<aw>, std::placeholders::_1, std::placeholders::_2, params...));
		}

		void run_single_passes()
		{
			//context_t<aw> context = { *linker, *bin, obf_routines, additional_routines };

			for (auto& routine : obf_routines)
			{
				for (auto& block : routine.m_routine.blocks)
					for (auto& inst : block.instructions)
						inst.redecode();

				/*routine.m_routine.blocks.sort([](dasm::block_t<aw>& left, dasm::block_t<aw>& right)
					{
						return left.rva_start < right.rva_start;
					});*/

				for (auto pass : single_passes)
				{
					pass(routine.m_routine, *this);
				}

				/*for (auto block_it = routine.m_routine.blocks.begin(); block_it != routine.m_routine.blocks.end(); ++block_it)
				{
					for (auto inst_it = block_it->instructions.begin(); inst_it != block_it->instructions.end(); ++inst_it)
					{
						auto cat = xed_decoded_inst_get_category(&inst_it->decoded_inst);

						if (cat == XED_CATEGORY_COND_BR)
						{
							if (!(inst_it->flags & dasm::inst_flag::block_terminator))
							{
								std::printf("was not block terminator. %X\n", inst_it->original_rva);
							}
							if (std::next(inst_it) != block_it->instructions.end())
							{
								std::printf("was not last instruction. %X\n", inst_it->original_rva);
							}
						}
					}
				}*/
			}

		}

		// These two functions REQUIRE that the order is not changed between their calls
		// Must be called one after the other
		//
		uint64_t place_routines()
		{
			uint64_t rva = bin->next_section_rva();
			auto base = rva;
			for (auto& routine : obf_routines)
			{
				
				for (auto block_it = routine.m_routine.blocks.begin(); block_it != routine.m_routine.blocks.end(); ++block_it)
				{
					if (block_it == routine.m_routine.entry_block)
						linker->set_link_addr(routine.m_routine.entry_link, rva);

					block_it->place_in_binary(rva, linker);

					rva = align_up(rva, block_alignment);
				}

				rva = align_up(rva, func_alignment);
			}

			for (auto& routine : additional_routines)
			{

				for (auto block_it = routine.blocks.begin(); block_it != routine.blocks.end(); ++block_it)
				{
					if (block_it == routine.entry_block)
						linker->set_link_addr(routine.entry_link, rva);

					block_it->place_in_binary(rva, linker);

					rva = align_up(rva, block_alignment);
				}

				rva = align_up(rva, func_alignment);
			}

			return bin->append_section(".OBFCODE", rva - base, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE, true);
		}
		void encode_routines(uint64_t rva)
		{
			//uint64_t rva = bin->append_section(".TEST", section_size, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE, true);
			auto dest = bin->mapped_image + rva;
			for (auto& routine : obf_routines)
			{
				for (auto& block : routine.m_routine.blocks)
				{
					block.encode_in_binary(bin, linker, &dest);

					dest = align_up_ptr(dest, block_alignment);
				}

				dest = align_up_ptr(dest, func_alignment);

				if (0 && routine.original_space >= 15)
				{
					int32_t random = rand() % 0xFFFF;
					uint32_t rva = routine.m_routine.entry_block->rva_start;
					uint32_t off = encode_inst_in_place(
						bin->mapped_image + rva,
						addr_width::machine_state<aw>::value,
						XED_ICLASS_LEA,
						addr_width::bits<aw>::value,
						xed_reg(max_reg_width<XED_REG_RAX, aw>::value),
						xed_mem_bd(
							max_reg_width<XED_REG_RIP, aw>::value,
							xed_disp(-static_cast<int32_t>(rva + 7) + random, 32),
							addr_width::bits<aw>::value
						)
					);
					off += encode_inst_in_place(
						bin->mapped_image + rva + off,
						addr_width::machine_state<aw>::value,
						XED_ICLASS_ADD,
						addr_width::bits<aw>::value,
						xed_reg(max_reg_width<XED_REG_RAX, aw>::value),
						xed_simm0(linker->get_link_addr(routine.m_routine.entry_block->link) - random, 32)
					);
					encode_inst_in_place(
						bin->mapped_image + rva + off,
						addr_width::machine_state<aw>::value,
						XED_ICLASS_JMP,
						addr_width::bits<aw>::value,
						xed_reg(max_reg_width<XED_REG_RAX, aw>::value)
					);
					
				}
				else
				{

					// Put a jump at the location of the original function, in case we didnt disassemble something
					//
					int32_t disp = linker->get_link_addr(routine.m_routine.entry_block->link) - routine.m_routine.entry_block->rva_start - 5;
					encode_inst_in_place(
						bin->mapped_image + routine.m_routine.entry_block->rva_start,
						addr_width::machine_state<aw>::value,
						XED_ICLASS_JMP,
						32,
						xed_relbr(disp, 32)
					);
				}
			}

			for (auto& routine : additional_routines)
			{
				for (auto& block : routine.blocks)
				{
					block.encode_in_binary(bin, linker, &dest);

					dest = align_up_ptr(dest, block_alignment);
				}

				dest = align_up_ptr(dest, block_alignment);

				dest = align_up_ptr(dest, func_alignment);
			}

		}

		uint64_t place_data()
		{
			uint64_t rva = bin->next_section_rva();
			auto base = rva;
			for (auto& data_chunk : data_chunks)
			{
				data_chunk.place_in_binary(rva);
				va = align_up(rva, 0x8);
			}
			return bin->append_section(".OBFDATA", rva - base, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE, true);
		}
		void write_data(uint64_t rva)
		{
			for (auto& data_chunk : data_chunks)
			{
				data_chunk.write_to_binary(rva);
				rva = align_up(rva, 0x8);
			}
		}

		void compile()
		{
			uint64_t data_rva = 0;
			auto code_rva = place_routines();

			if (data_chunks.size())
				data_rva = place_data();

			encode_routines(code_rva);

			if (data_chunks.size())
				write_data(data_rva);
		}
	};
}


//void meme()
//{
//	dasm::routine_t<addr_width::x64> routine;
//	obf::routine_t<addr_width::x64> obfr(routine);
//	obf::obf_t<addr_width::x64> ctx;
//	ctx.bin = nullptr;
//	ctx.linker = nullptr;
//	obfr.mutation_pass<obf::mba_t<>>(ctx);
//}