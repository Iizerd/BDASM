


#pragma once


/*
	TODO: going to break with trailing calls.... Probably a huge problem already
			im just not seeing it. Going break on INT3 for now...
			I think that the proper way to handle this is with dpattern.h
*/



#pragma once


extern "C"
{
#include <xed/xed-interface.h>
}

#include <atomic>
#include <mutex>
#include <functional>

#include "symbol.h"
#include "addr_width.h"
#include "inst.h"
#include "inst_block.h"
#include "size_casting.h"
#include "pex.h"

namespace dasm
{

	// This just makes things easier... holy shit enum class so close to being useful,,, but then just isnt.
	namespace lookup_table_entry
	{
		typedef uint8_t type;

		constexpr uint8_t none = 0;

		// Is the start of an instruction
		//
		constexpr uint8_t is_inst_start = (1 << 0);

		// Is this address inside a decoded inst.
		//
		constexpr uint8_t is_decoded = (1 << 1);

		// This is to prevent recursive routines messing stuff up
		//
		constexpr uint8_t is_self = (1 << 2);
	}

	template<addr_width::type Addr_width = addr_width::x64>
	struct decoder_context_t
	{
		struct
		{
			// Disassembler will follow calls and queue them for disassembly
			//
			bool recurse_calls;

			// This is for combining blocks that surround dead code. It rarely happens and
			// the most likely case for two blocks not being together is that they are from
			// different functions and the disassembler just didnt see that because it's
			// pretty crude
			//
			int32_t block_combination_threshold;
		}settings;

		//symbol_table_t* symbol_table;
		pex::binary_t<Addr_width>* binary_interface;

		const uint8_t* raw_data_start;
		const uint64_t raw_data_size;
		std::function<void(uint64_t)> report_routine_rva;

		explicit decoder_context_t(pex::binary_t<Addr_width>* binary, std::function<void(uint64_t)> rva_reporter = nullptr)
			: binary_interface(binary),
			report_routine_rva(rva_reporter),
			raw_data_start(binary->mapped_image),
			raw_data_size(binary->optional_header.get_size_of_image())
		{ 
			settings.recurse_calls = false;
			settings.block_combination_threshold = 0;
		}
		explicit decoder_context_t(decoder_context_t const& to_copy)
			: binary_interface(to_copy.binary_interface),
			report_routine_rva(to_copy.report_routine_rva),
			raw_data_start(to_copy.raw_data_start),
			raw_data_size(to_copy.raw_data_size)
		{
			settings.recurse_calls = to_copy.settings.recurse_calls;
			settings.block_combination_threshold = to_copy.settings.block_combination_threshold;
		}

		bool validate_rva(uint64_t rva)
		{
			return (rva < raw_data_size);
		}
	};

	class decode_lookup_table
	{
		const uint64_t m_table_size;
		lookup_table_entry::type* m_entries;
		std::vector<uint32_t> m_clear_indices;
	public:
		explicit decode_lookup_table(uint64_t table_size)
			: m_table_size(table_size)
		{
			m_entries = (lookup_table_entry::type*)calloc(table_size, 1);
			m_clear_indices.reserve(table_size / 10);
		}
		~decode_lookup_table()
		{
			free(m_entries);
		}
		finline void clear()
		{
			for (auto i : m_clear_indices)
				m_entries[i] = lookup_table_entry::none;

			m_clear_indices.clear();
		}
		finline bool is_self(uint64_t rva) const
		{
			return static_cast<bool>(m_entries[rva] & lookup_table_entry::is_self);
		}
		finline bool is_decoded(uint64_t rva) const
		{
			return static_cast<bool>(m_entries[rva] & lookup_table_entry::is_decoded);
		}
		finline bool is_inst_start(uint64_t rva) const
		{
			return static_cast<bool>(m_entries[rva] & lookup_table_entry::is_inst_start);
		}
		finline void update_inst(uint64_t rva, int32_t inst_len)
		{
			m_entries[rva] |= lookup_table_entry::is_inst_start;
			m_clear_indices.push_back(rva);
			for (int32_t i = 0; i < inst_len; i++)
			{
				m_entries[rva + i] |= lookup_table_entry::is_decoded;
				m_clear_indices.push_back(rva + i);
			}
		}
	};

	template<addr_width::type Addr_width = addr_width::x64>
	bool iform_switch_nullsub(decoder_context_t<Addr_width>* context, decode_lookup_table* lookup_table, inst_t<Addr_width>& inst, uint64_t rva)
	{
		return true;
	}

	template<addr_width::type Addr_width = addr_width::x64>
	class iform_switch_t
	{
		using Cb_type = std::function<bool(decoder_context_t<Addr_width>* context, inst_t<Addr_width>& inst, uint64_t rva)>;
		Cb_type m_cb_table[XED_IFORM_LAST];
	public:
		constexpr iform_switch_t(std::initializer_list<std::pair<std::initializer_list<xed_iform_enum_t>, Cb_type> > list)
		{
			for (uint32_t i = 0; i < XED_IFORM_LAST; ++i)
				m_cb_table[i] = iform_switch_nullsub<Addr_width>;

			for (auto& ele : list)
			{
				for (auto& iform : ele.first)
					set(iform, ele.second);
			}
		}
		void set(xed_iform_enum_t iform, Cb_type cb)
		{
			m_cb_table[iform] = cb;
		}
		bool operator()(xed_iform_enum_t iform, decoder_context_t<Addr_width>* context, inst_t<Addr_width>& inst, uint64_t rva)
		{
			return m_cb_table[iform](context, inst, rva);
		}
	};

	// A collection of blocks
	template<addr_width::type Addr_width = addr_width::x64>
	class inst_routine_t
	{
		uint64_t m_max_rva;

	public:
		std::list<inst_block_t<Addr_width> > blocks;
		uint64_t range_start = 0;
		uint64_t range_end = 0;

		// So we know what block is the entry for this function
		//
		std::list<inst_block_t<Addr_width> >::iterator entry_it;
		uint64_t entry_rva = 0;

		bool complete_disassembly = true;

		bool rva_in_function(uint64_t rva)
		{
			return (rva >= entry_rva && rva < m_max_rva);
		}

		void block_trace()
		{
			for (auto& block : blocks)
			{
				std::printf("Block[%p:%p]\n", block.start, block.end);
			}
		}
		void decode_block(decoder_context_t<Addr_width>* context, uint64_t rva, decode_lookup_table* lookup_table)
		{
			auto& current_block = blocks.emplace_back();
			current_block.start = rva;

			auto current_block_it = std::prev(blocks.end());

			while (!lookup_table->is_inst_start(rva) && rva != m_max_rva)
			{
				auto& inst = current_block.instructions.emplace_back();

				int32_t ilen = inst.decode(const_cast<uint8_t*>(context->raw_data_start + rva), context->raw_data_size - rva);
				if (ilen == 0)
				{
					std::printf("Failed to decode, 0 inst length. RVA: 0x%016X, Block Start: 0x%016X, Size: %llu\n", rva, current_block.start, current_block.instructions.size());
					block_trace();
					break;
				}

				//std::printf("IClass: %s\n", xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));

				inst.my_symbol = context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(rva);

				lookup_table->update_inst(rva, ilen);

				bool has_reloc = context->binary_interface->symbol_table->inst_uses_reloc(rva, ilen, inst.additional_data.reloc.offset_in_inst, inst.additional_data.reloc.type);

				// Parse operands for rip relative addressing and relocs
				//
				uint32_t num_operands = xed_decoded_inst_noperands(&inst.decoded_inst);
				auto decoded_inst_inst = xed_decoded_inst_inst(&inst.decoded_inst);
				for (uint32_t i = 0; i < num_operands; ++i)
				{
					auto operand_name = xed_operand_name(xed_inst_operand(decoded_inst_inst, i));
					if (XED_OPERAND_MEM0 == operand_name || XED_OPERAND_AGEN == operand_name)
					{
						auto base_reg = xed_decoded_inst_get_base_reg(&inst.decoded_inst, 0);
						if (get_max_reg_size<XED_REG_RIP, Addr_width>::value == base_reg)
						{
							inst.used_symbol = context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
								rva + ilen + xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)
							);
							inst.flags |= inst_flag::disp;
						}
						else if (XED_REG_INVALID == base_reg && 
							xed_decoded_inst_get_memory_displacement_width_bits(&inst.decoded_inst, 0) == addr_width::bits<Addr_width>::value)
						{
							if (has_reloc)
							{
								inst.used_symbol = context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
									static_cast<uint64_t>(xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)) -
									context->binary_interface->optional_header.get_image_base()
								);
								inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
								inst.flags |= inst_flag::reloc_disp;
							}
							else
							{
								complete_disassembly = false;
							}
						}
					}
					else if (has_reloc && XED_OPERAND_IMM0 == operand_name && 
						xed_decoded_inst_get_immediate_width_bits(&inst.decoded_inst) == addr_width::bits<Addr_width>::value)
					{
						inst.used_symbol = context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
							xed_decoded_inst_get_unsigned_immediate(&inst.decoded_inst) -
							context->binary_interface->optional_header.get_image_base()
						);
						inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
						inst.flags |= inst_flag::reloc_imm;
					}
				}

				rva += ilen;

				// Follow control flow
				//
				auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
				if (cat == XED_CATEGORY_COND_BR)
				{
					int32_t br_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
					uint64_t taken_rva = rva + br_disp;

					if (!context->validate_rva(taken_rva))
					{
						std::printf("Conditional branch to invalid rva.\n");
						goto ExitInstDecodeLoop;
					}

					inst.used_symbol = context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(taken_rva);
					inst.flags |= inst_flag::rel_br;

					if (!lookup_table->is_inst_start(taken_rva) && rva_in_function(taken_rva))
					{
						decode_block(context, taken_rva, lookup_table);
					}
				}
				else if (cat == XED_CATEGORY_UNCOND_BR)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_JMP_GPRv:
						// Jump table.
						//
						complete_disassembly = false;
						std::printf("Unhandled inst[%08X]: XED_IFORM_JMP_GPRv.\n", rva - ilen);
						goto ExitInstDecodeLoop;
					case XED_IFORM_JMP_MEMv:
						if (!inst.used_symbol)
						{
							complete_disassembly = false;
							std::printf("Unhandled inst[%08X]: XED_IFORM_JMP_MEMv.\n", rva - ilen);
						}
						goto ExitInstDecodeLoop;
					case XED_IFORM_JMP_RELBRb:
					case XED_IFORM_JMP_RELBRd:
					case XED_IFORM_JMP_RELBRz:
					{
						int32_t jmp_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
						uint64_t dest_rva = rva + jmp_disp;

						if (!context->validate_rva(dest_rva))
						{
							std::printf("Unconditional branch to invalid rva.\n");
							goto ExitInstDecodeLoop;
						}
						inst.used_symbol = context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= inst_flag::rel_br;

						/*if (!lookup_table->is_inst_start(dest_rva) && rva_in_function(dest_rva))
						{
							decode_block(context, dest_rva, lookup_table);
						}*/

						if (!lookup_table->is_inst_start(dest_rva))
						{
							if (rva_in_function(dest_rva))
								decode_block(context, dest_rva, lookup_table);
							else
								context->report_routine_rva(dest_rva); // This is most likely an optimized jmp to a function at end of current function
						}

						goto ExitInstDecodeLoop;
					}
					case XED_IFORM_JMP_FAR_MEMp2:
					case XED_IFORM_JMP_FAR_PTRp_IMMw:
						complete_disassembly = false;
						std::printf("Unhandled inst[%08X]: JMP_FAR_MEM/PTR.\n", rva - ilen);
						goto ExitInstDecodeLoop;
					}
				}
				else if (cat == XED_CATEGORY_CALL && context->settings.recurse_calls)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_CALL_NEAR_GPRv:
						// Call table?!
						//
						complete_disassembly = false;
						std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_GPRv.\n", rva - ilen);
						break;
					case XED_IFORM_CALL_NEAR_MEMv:
						// Import or call to absolute address...
						//
						if (!inst.used_symbol)
						{
							complete_disassembly = false;
							std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_MEMv.\n", rva - ilen);
						}
						break;

					case XED_IFORM_CALL_NEAR_RELBRd:
					case XED_IFORM_CALL_NEAR_RELBRz:
					{
						int32_t call_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
						uint64_t dest_rva = rva + call_disp;
						if (!context->validate_rva(dest_rva))
						{
							std::printf("Call to invalid rva.\n");
							goto ExitInstDecodeLoop;
						}

						//std::printf("Found call at 0x%X, 0x%X\n", rva - ilen, dest_rva);

						inst.used_symbol = context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= inst_flag::rel_br;

						if (!lookup_table->is_self(dest_rva))
						{
							context->report_routine_rva(dest_rva);
						}
						break;
					}
					case XED_IFORM_CALL_FAR_MEMp2:
					case XED_IFORM_CALL_FAR_PTRp_IMMw:
						complete_disassembly = false;
						std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_FAR_MEM/PTR.\n", rva - ilen);
						break;
					}
				}
				else if (cat == XED_CATEGORY_RET)
				{
					break;
				}
				else if (XED_ICLASS_INT3 == xed_decoded_inst_get_iclass(&inst.decoded_inst)/* && current_block.instructions.size() > 1*/)
				{
					/*auto last = current_block.instructions.end();
					std::advance(last, -2);
					auto prev_iclass = xed_decoded_inst_get_iclass(&last->decoded_inst);
					if (XED_ICLASS_JMP == prev_iclass || XED_ICLASS_CALL_NEAR == prev_iclass)
					{*/
						break;
					//}
				}
			}

		ExitInstDecodeLoop:

			current_block.end = rva;

			for (auto it = blocks.begin(); it != blocks.end(); ++it)
			{
				if (it->start == rva && it != current_block_it)
				{
					it->instructions.splice(it->instructions.begin(), current_block.instructions);
					it->start = current_block.start;
					blocks.erase(current_block_it);
				}
			}
		}
		void decode(decoder_context_t<Addr_width>* context, decode_lookup_table* lookup_table, uint64_t rva)
		{
			if (!context->validate_rva(rva))
			{
				std::printf("Attempting to decode routine at invalid rva.\n");
				return;
			}

			entry_rva = rva;
			//auto& sym = context->binary_interface->symbol_table->unsafe_get_symbol_for_rva(rva);
			pex::image_runtime_function_it_t runtime_func(nullptr);
			if (context->binary_interface->symbol_table->unsafe_get_symbol_for_rva(rva).has_func_data())
			{
				runtime_func.set(context->binary_interface->mapped_image +
					context->binary_interface->symbol_table->get_func_data(rva).runtime_function_rva);

				m_max_rva = runtime_func.get_end_address();
			}
			else
			{
				m_max_rva = context->raw_data_size;
			}

			decode_block(context, rva, lookup_table);

			blocks.sort([](inst_block_t<Addr_width> const& b1, inst_block_t<Addr_width> const& b2) -> bool
				{
					return (b1.start < b2.start);
				});

			for (auto it = blocks.begin(); it != blocks.end(); ++it)
			{
				auto next = std::next(it);
				if (next == blocks.end())
					break;

				if (next->start - it->end <= context->settings.block_combination_threshold)
				{
					it->instructions.splice(it->instructions.end(), next->instructions);
					it->end = next->end;
					blocks.erase(next);
				}
			}

			for (auto it = blocks.begin(); it != blocks.end(); ++it)
			{
				if (it->start = entry_rva)
				{
					entry_it = it;
					break;
				}
			}

			// Im thinking maybe do a "post processing" pass here to discover blocks that really are from separate functions
			// Maybe, one block ends with a jump which goes somewhere far away.
			//

			range_start = context->binary_interface->symbol_table->get_symbol(blocks.front().instructions.front().my_symbol).address;
			range_end = context->binary_interface->symbol_table->get_symbol(blocks.back().instructions.back().my_symbol).address + blocks.back().instructions.back().length();

		}


		void promote_relbrs()
		{
			for (auto& block : blocks)
			{
				for (auto& inst : block.instructions)
				{
					auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
					if (cat == XED_CATEGORY_UNCOND_BR)
					{
						xed_decoded_inst_set_branch_displacement_bits(&inst.decoded_inst, 0, 32);
						inst.redecode();
					}
					else if (cat == XED_CATEGORY_COND_BR)
					{
						switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
						{
						case XED_IFORM_JMP_RELBRb:
						case XED_IFORM_JMP_RELBRd:
						case XED_IFORM_JMP_RELBRz:
							xed_decoded_inst_set_branch_displacement_bits(&inst.decoded_inst, 0, 32);
							inst.redecode();
						}
					}
				}
			}
		}
		void force_merge_blocks()
		{
			if (blocks.size() > 1)
			{
				auto start = blocks.begin();

				for (auto it = std::next(blocks.begin()); it != blocks.end();)
				{
					auto next = std::next(it);
					std::printf("Merging blocks with gap: %u\n", next->end - it->start);
					start->instructions.splice(start->instructions.end(), it->instructions);
					blocks.erase(it);
					it = next;
				}
			}
		}
	};

	template<addr_width::type Addr_width = addr_width::x64>
	class dasm_thread_t
	{
		std::thread* m_thread;

		std::atomic_bool m_signal_start;
		std::atomic_bool m_signal_shutdown;

		std::mutex m_queued_routines_lock;
		std::vector<uint64_t> m_queued_routines;

		decoder_context_t<Addr_width>* m_decoder_context;

		decode_lookup_table m_lookup_table;
	public:
		inline static std::atomic_uint32_t queued_routine_count;
		std::list<inst_routine_t<Addr_width> > finished_routines;

		explicit dasm_thread_t(decoder_context_t<Addr_width>* context)
			: m_decoder_context(context),
			m_signal_start(false),
			m_signal_shutdown(false),
			m_lookup_table(m_decoder_context->raw_data_size)
		{
			m_thread = new std::thread(&dasm_thread_t::run, this);
		}
		explicit dasm_thread_t(dasm_thread_t const& to_copy)
			: m_lookup_table(to_copy.m_decoder_context->raw_data_size)
		{
			std::printf("Copy constructor called. This is bad.\n");
		}
		~dasm_thread_t()
		{
			if (m_thread->joinable())
				m_thread->join();
			delete m_thread;
		}
		bool pop_queued_routine(uint64_t& routine_rva)
		{
			if (!m_signal_start)
				return false;

			std::lock_guard g(m_queued_routines_lock);
			if (m_queued_routines.size())
			{
				routine_rva = m_queued_routines.back();
				m_queued_routines.pop_back();
				return true;
			}
			return false;
		}

		void queue_routine(uint64_t routine_rva)
		{
			++queued_routine_count;
			std::lock_guard g(m_queued_routines_lock);
			m_queued_routines.emplace_back(routine_rva);
		}

		void start()
		{
			m_signal_start = true;
		}
		void stop()
		{
			m_signal_shutdown = true;
		}

		void run()
		{
			while (!m_signal_shutdown)
			{
				uint64_t routine_rva = 0;
				if (pop_queued_routine(routine_rva))
				{
					finished_routines.emplace_back().decode(m_decoder_context, &m_lookup_table, routine_rva);
					m_lookup_table.clear();
					--queued_routine_count;
					continue; //Skip the sleep.
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		}
	};

	template<addr_width::type Addr_width = addr_width::x64, uint8_t Thread_count = 1>
	class dasm_t
	{
		decoder_context_t<Addr_width>* m_context;

		uint8_t m_next_thread;

		std::vector<dasm_thread_t<Addr_width> > m_threads;

		std::atomic_bool* m_routine_lookup_table;

	public:

		std::list<inst_routine_t<Addr_width> > completed_routines;

		explicit dasm_t(decoder_context_t<Addr_width>* context)
			: m_next_thread(0)
		{
			m_context = context;
			m_context->report_routine_rva = std::bind(&dasm_t::add_routine, this, std::placeholders::_1);
			m_routine_lookup_table = new std::atomic_bool[m_context->raw_data_size];
			for (uint32_t i = 0; i < m_context->raw_data_size; i++)
				m_routine_lookup_table[i] = false;

			m_threads.reserve(Thread_count * 2);
			for (uint8_t i = 0; i < Thread_count; ++i)
				m_threads.emplace_back(m_context);
		}
		~dasm_t()
		{
			if (m_routine_lookup_table)
				delete[] m_routine_lookup_table;
		}

		void add_routine(uint64_t routine_rva)
		{
			if (m_routine_lookup_table[routine_rva] || m_context->binary_interface->symbol_table->is_executable(routine_rva))
				return;

			m_routine_lookup_table[routine_rva] = true;

			m_threads[m_next_thread].queue_routine(routine_rva);
			m_next_thread++;
			if (m_next_thread >= Thread_count)
				m_next_thread = 0;
		}

		void add_multiple_routines(std::vector<uint64_t> const& routines_rvas)
		{
			for (auto rva : routines_rvas)
			{
				if (m_context->validate_rva(rva))
					add_routine(rva);
			}
		}

		void run()
		{
			for (auto& thread : m_threads)
				thread.start();
		}

		void wait_for_completion()
		{
			while (dasm_thread_t<Addr_width>::queued_routine_count)
				std::this_thread::sleep_for(std::chrono::milliseconds(1));

			for (auto& thread : m_threads)
			{
				completed_routines.splice(completed_routines.end(), thread.finished_routines);
				thread.stop();
			}


		}

		uint32_t count_instructions()
		{
			uint32_t count = 0;
			for (auto& routine : completed_routines)
			{
				for (auto& block : routine.blocks)
				{
					for (auto& inst : block.instructions)
						count++;
				}
			}
			return count;
		}

		void print_details()
		{
			std::printf("decoded %llu routines.\n", completed_routines.size());

			uint32_t inst_count = 0;

			for (auto& routine : completed_routines)
				for (auto& block : routine.blocks)
					inst_count += block.instructions.size();

			std::printf("with %u instructions.\n", inst_count);
		}
	};

}

