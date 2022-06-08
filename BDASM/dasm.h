


#pragma once


/*
	This version of dasm utilized multithreading to speed up the disassembly process.
	Unfortunately, because the symbol table requires locking to access, I put this here
	and reverted the project to single thread because it is honestly faster at this point.

	One option I will persue is to rebuild the symbol table structure so it locks itself.
	But only does so when its absolutely needed. This way,

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

	using fn_report_function_rva = void(*)(uint64_t);

	struct decoder_context_t
	{
		struct
		{
			bool recurse_calls;
		}settings;

		symbol_table_t* symbol_table;

		const uint8_t* raw_data_start;
		const uint8_t* raw_data_end;
		const uint64_t raw_data_size;
		const uint64_t base_adjustment;
		std::function<void(uint64_t)> report_function_rva;

		explicit decoder_context_t(uint8_t* data, uint64_t data_size, symbol_table_t* sym_table, std::function<void(uint64_t)> rva_reporter = nullptr, uint64_t adjustment = 0)
			: raw_data_start(data),
			raw_data_end(data + data_size),
			raw_data_size(data_size),
			base_adjustment(adjustment),
			symbol_table(sym_table),
			report_function_rva(rva_reporter)
		{ }
		explicit decoder_context_t(decoder_context_t const& to_copy)
			: raw_data_start(to_copy.raw_data_start),
			raw_data_end(to_copy.raw_data_end),
			raw_data_size(to_copy.raw_data_size),
			base_adjustment(to_copy.base_adjustment),
			symbol_table(to_copy.symbol_table),
			report_function_rva(to_copy.report_function_rva)
		{ }

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

	// A collection of blocks
	template<address_width Addr_width = address_width::x64>
	class inst_routine_t
	{
	public:
		std::list<inst_block_t<Addr_width> > blocks;
		uint64_t start;
		uint64_t end;

		void block_trace()
		{
			for (auto& block : blocks)
			{
				std::printf("Block[%p:%p]\n", block.start, block.end);
			}
		}
		void decode_block(decoder_context_t* context, uint64_t rva, decode_lookup_table* lookup_table)
		{
			auto& current_block = blocks.emplace_back();
			current_block.start = rva;

			auto current_block_it = std::prev(blocks.end());

			while (!lookup_table->is_inst_start(rva))
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

				inst.my_symbol = context->symbol_table->get_symbol_index_for_rva_unsafe(rva);

				lookup_table->update_inst(rva, ilen);

				rva += ilen;

				// Parse operands for rip relative addressing
				//
				uint32_t num_operands = xed_decoded_inst_noperands(&inst.decoded_inst);
				auto decoded_inst_inst = xed_decoded_inst_inst(&inst.decoded_inst);
				for (uint32_t i = 0; i < num_operands; ++i)
				{
					auto operand_name = xed_operand_name(xed_inst_operand(decoded_inst_inst, i));
					if ((XED_OPERAND_MEM0 == operand_name || XED_OPERAND_AGEN == operand_name) && 
						get_max_reg_size<XED_REG_RIP, Addr_width>::value == xed_decoded_inst_get_base_reg(&inst.decoded_inst, 0))
					{
						int64_t rip_delta = xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0);
						std::printf("Rip Delta %lld\n", rip_delta);
						inst.used_symbol = context->symbol_table->get_symbol_index_for_rva_unsafe(rva + rip_delta);
						inst.flags |= inst_flag::disp;
					}
				}
				


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

					inst.used_symbol = context->symbol_table->get_symbol_index_for_rva_unsafe(taken_rva);
					inst.flags |= inst_flag::rel_br;

					if (!lookup_table->is_inst_start(taken_rva))
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

						goto ExitInstDecodeLoop;
					case XED_IFORM_JMP_MEMv:
						// Import or jump to absolute address...
						//

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
						inst.used_symbol = context->symbol_table->get_symbol_index_for_rva_unsafe(dest_rva);
						inst.flags |= inst_flag::rel_br;

						if (!lookup_table->is_inst_start(dest_rva))
						{
							decode_block(context, dest_rva, lookup_table);
						}

						goto ExitInstDecodeLoop;
					}
					case XED_IFORM_JMP_FAR_MEMp2:
					case XED_IFORM_JMP_FAR_PTRp_IMMw:
						std::printf("Jump we dont handle.\n");

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
						break;
					case XED_IFORM_CALL_NEAR_MEMv:
						// Import or call to absolute address...
						//
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

						inst.used_symbol = context->symbol_table->get_symbol_index_for_rva_unsafe(dest_rva);
						inst.flags |= inst_flag::rel_br;

						if (!lookup_table->is_self(dest_rva))
						{
							context->report_function_rva(dest_rva);
						}
						break;
					}
					case XED_IFORM_CALL_FAR_MEMp2:
					case XED_IFORM_CALL_FAR_PTRp_IMMw:
						std::printf("Call we dont handle.\n");
						break;
					}
				}
				else if (cat == XED_CATEGORY_RET)
				{
					break;
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
		void decode(decode_lookup_table* lookup_table, decoder_context_t* context, uint64_t rva)
		{
			if (!context->validate_rva(rva))
			{
				std::printf("Attempting to decode routine at invalid rva.\n");
				return;
			}

			//decode_lookup_table lookup_table(context->raw_data_size);
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

				if (it->end == next->start)
				{
					it->instructions.splice(it->instructions.end(), next->instructions);

					blocks.erase(next);
				}
			}

			start = context->symbol_table->get_symbol(blocks.front().instructions.front().my_symbol).address;
			end = context->symbol_table->get_symbol(blocks.back().instructions.back().my_symbol).address + blocks.back().instructions.back().length();
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

	template<address_width Addr_width = address_width::x64>
	class dasm_thread_t
	{
		std::thread* m_thread;

		std::atomic_bool m_signal_start;
		std::atomic_bool m_signal_shutdown;

		std::mutex m_queued_routines_lock;
		std::vector<uint64_t> m_queued_routines;

		decoder_context_t* m_decoder_context;

		decode_lookup_table m_lookup_table;
	public:
		inline static std::atomic_uint32_t queued_routine_count;
		std::list<inst_routine_t<Addr_width> > finished_routines;

		explicit dasm_thread_t(decoder_context_t* context)
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
			//std::printf("queued for %p\n", this);
			++queued_routine_count;
			std::lock_guard g(m_queued_routines_lock);
			m_queued_routines.push_back(routine_rva);
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
					finished_routines.emplace_back().decode(&m_lookup_table, m_decoder_context, routine_rva);
					m_lookup_table.clear();
					--queued_routine_count;
					continue; //Skip the sleep.
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		}
	};

	template<address_width Addr_width = address_width::x64, uint8_t Thread_count = 1>
	class dasm_t
	{
		decoder_context_t* m_context;

		uint8_t m_next_thread;

		std::vector<dasm_thread_t<Addr_width> > m_threads;

		std::atomic_bool* m_routine_lookup_table;

	public:

		std::list<inst_routine_t<Addr_width> > completed_routines;

		std::function<bool(uint64_t)> is_executable;

		explicit dasm_t(decoder_context_t* context)
			: m_next_thread(0)
		{
			m_context = context;
			m_context->report_function_rva = std::bind(&dasm_t::add_routine, this, std::placeholders::_1);
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
			if (m_routine_lookup_table[routine_rva] || !is_executable(routine_rva))
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







