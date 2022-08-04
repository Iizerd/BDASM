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


	template<addr_width::type Addr_width = addr_width::x64>
	class routine_t;

	template<addr_width::type Addr_width = addr_width::x64, uint32_t Thread_count = 1>
	class obf_t;

	template<addr_width::type Addr_width = addr_width::x64>
	struct context_t
	{
		dasm::linker_t& linker;
		pex::binary_t<Addr_width>& bin;
		std::list<routine_t<Addr_width>>& obf_routine_list;
		std::list<dasm::routine_t<Addr_width>>& additional_routines;
	};

	template<addr_width::type Addr_width>
	class routine_t
	{
	public:
		dasm::routine_t<Addr_width>& m_routine;

		// Space the original function occupied, how much we have to place a jump
		//
		uint32_t original_space;
	public:

		routine_t(dasm::routine_t<Addr_width>& routine, uint32_t space)
			: m_routine(routine)
			, original_space(space)
		{}

		template<typename Pass_type, typename... Params>
		pass_status_t mutation_pass(obf_t<Addr_width>& ctx, Params... params)
		{
			return Pass_type::pass(m_routine, ctx, params...);
		}
	};

	//https://www.youtube.com/watch?v=pXwbj_ZPKwg&ab_channel=VvporTV
	//
	template<addr_width::type Addr_width, uint32_t Thread_count>
	class obf_t
	{
		std::vector<std::function<pass_status_t(dasm::routine_t<Addr_width>&, obf::context_t<Addr_width>&)>> single_passes;

		dasm::decoder_context_t<Addr_width>* m_decoder_context;

		dasm::linker_t* m_linker;
	public:

		dasm::dasm_t<Addr_width, Thread_count>* dasm;

		pex::binary_t<Addr_width>* bin;

		std::list<routine_t<Addr_width>> obf_routines;

		// These are routines that are added after the fact and we dont want to apply obfuscation passes to.
		//
		std::list<dasm::routine_t<Addr_width>> additional_routines;

		obf_t()
			: dasm(nullptr)
			, m_decoder_context(nullptr)
			, m_linker(nullptr)
			, bin(new pex::binary_t<Addr_width>)
		{}

		~obf_t()
		{
			if (dasm)
				delete dasm;
			if (m_decoder_context)
				delete m_decoder_context;
			if (m_linker)
				delete m_linker;

			delete bin;
		}

		bool routine_analysis(dasm::routine_t<Addr_width>& routine, uint32_t& start_size)
		{
			uint32_t start = routine.entry_block->rva_start;
			uint32_t end = routine.entry_block->rva_end;
			start_size = end - start;

			std::vector<dasm::block_t<Addr_width>*> blocks;
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

			m_linker = new dasm::linker_t(bin->optional_header.get_size_of_image(), 0x10000);

			m_decoder_context = new dasm::decoder_context_t(bin);
			m_decoder_context->settings.recurse_calls = true;
			m_decoder_context->linker = m_linker;

			dasm = new dasm::dasm_t<Addr_width, Thread_count>(m_decoder_context);

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
		pass_status_t group_pass(context_t<Addr_width>& ctx, Params... params)
		{
			return Pass_type::pass(ctx, params...);
		}

		template<typename Pass_type, typename... Params>
		void register_single_pass(Params... params)
		{
			single_passes.push_back(std::bind(&Pass_type::template pass<Addr_width>, std::placeholders::_1, std::placeholders::_2, params...));
		}

		void run_single_passes()
		{
			context_t<Addr_width> context = { *m_linker, *bin, obf_routines, additional_routines };

			for (auto& routine : obf_routines)
			{
				for (auto& block : routine.m_routine.blocks)
					for (auto& inst : block.instructions)
						inst.redecode();

				/*routine.m_routine.blocks.sort([](dasm::block_t<Addr_width>& left, dasm::block_t<Addr_width>& right)
					{
						return left.rva_start < right.rva_start;
					});*/

				for (auto pass : single_passes)
				{
					pass(routine.m_routine, context);
				}

				//	//printf("\n\nROUTINE AT %X %u\n", routine.m_routine.entry_block->rva_start, routine.m_routine.blocks.size());
				//if (routine.m_routine.entry_block->rva_start == 0x1530)
				//	routine.m_routine.print_blocks();
				//	//int32_t alloc_size = 0x400;
				//	//auto pass_status = routine.mutation_pass<stack_allocation_t>(context, alloc_size);
				//	//std::printf("allocated with %X %d\n", alloc_size, pass_status);
				//	routine.mutation_pass< opaque_from_flags_t>(context);
				// Basic sanity check
				//
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
		uint32_t place()
		{
			uint64_t rva = bin->next_section_rva();
			auto base = rva;
			for (auto& routine : obf_routines)
			{
				
				for (auto block_it = routine.m_routine.blocks.begin(); block_it != routine.m_routine.blocks.end(); ++block_it)
				{
					if (block_it == routine.m_routine.entry_block)
						m_linker->set_link_addr(routine.m_routine.entry_link, rva);

					block_it->place_in_binary(rva, m_linker);
				}

				rva = align_up(rva, 0x10);
			}

			for (auto& routine : additional_routines)
			{

				for (auto block_it = routine.blocks.begin(); block_it != routine.blocks.end(); ++block_it)
				{
					if (block_it == routine.entry_block)
						m_linker->set_link_addr(routine.entry_link, rva);

					block_it->place_in_binary(rva, m_linker);
				}

				rva = align_up(rva, 0x10);
			}

			return rva - base;
		}
		void encode(uint32_t section_size)
		{
			uint64_t rva = bin->append_section(".TEST", section_size, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE, true);
			auto dest = bin->mapped_image + rva;
			for (auto& routine : obf_routines)
			{
				for (auto& block : routine.m_routine.blocks)
				{
					block.encode_in_binary(bin, m_linker, &dest);
				}

				dest = align_up_ptr(dest, 0x10);


				

				if (0 && routine.original_space >= 15)
				{
					int32_t random = rand() % 0xFFFF;
					uint32_t rva = routine.m_routine.entry_block->rva_start;
					uint32_t off = encode_inst_in_place(
						bin->mapped_image + rva,
						addr_width::machine_state<Addr_width>::value,
						XED_ICLASS_LEA,
						addr_width::bits<Addr_width>::value,
						xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
						xed_mem_bd(
							max_reg_width<XED_REG_RIP, Addr_width>::value,
							xed_disp(-static_cast<int32_t>(rva + 7) + random, 32),
							addr_width::bits<Addr_width>::value
						)
					);
					off += encode_inst_in_place(
						bin->mapped_image + rva + off,
						addr_width::machine_state<Addr_width>::value,
						XED_ICLASS_ADD,
						addr_width::bits<Addr_width>::value,
						xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value),
						xed_simm0(m_linker->get_link_addr(routine.m_routine.entry_block->link) - random, 32)
					);
					encode_inst_in_place(
						bin->mapped_image + rva + off,
						addr_width::machine_state<Addr_width>::value,
						XED_ICLASS_JMP,
						addr_width::bits<Addr_width>::value,
						xed_reg(max_reg_width<XED_REG_RAX, Addr_width>::value)
					);
					
				}
				else
				{

					// Put a jump at the location of the original function, in case we didnt disassemble something
					//
					int32_t disp = m_linker->get_link_addr(routine.m_routine.entry_block->link) - routine.m_routine.entry_block->rva_start - 5;
					encode_inst_in_place(
						bin->mapped_image + routine.m_routine.entry_block->rva_start,
						addr_width::machine_state<Addr_width>::value,
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
					block.encode_in_binary(bin, m_linker, &dest);
				}

				dest = align_up_ptr(dest, 0x10);
			}

		}
	};
}


//void meme()
//{
//	dasm::routine_t<addr_width::x64> routine;
//	obf::routine_t<addr_width::x64> obfr(routine);
//	obf::context_t<addr_width::x64> ctx;
//	ctx.bin = nullptr;
//	ctx.linker = nullptr;
//	obfr.mutation_pass<obf::mba_t<>>(ctx);
//}