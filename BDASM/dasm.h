


#pragma once


/*
	A + B | ~A - ~B

	~A | A ^ ~0
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

		}settings;

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
		}
		explicit decoder_context_t(decoder_context_t const& to_copy)
			: binary_interface(to_copy.binary_interface),
			report_routine_rva(to_copy.report_routine_rva),
			raw_data_start(to_copy.raw_data_start),
			raw_data_size(to_copy.raw_data_size)
		{
			settings.recurse_calls = to_copy.settings.recurse_calls;
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

	// Make an iterator for this so we can iterate without worrying about blocks...
	// The blocks by the way are not basic blocks, they are position independent blocks.
	// Meaning their are jumped to, and jump out by their end. They can be encoded and
	// placed anywhere as long as all symbols are updated.
	//
	template<addr_width::type Addr_width = addr_width::x64>
	class routine_t
	{
	public:
		std::list<inst_list_t<Addr_width> > blocks;
		uint64_t range_start;
		uint64_t range_end;

		uint64_t original_entry_rva;
		std::vector<uint32_t> entry_symbols;
		void promote_relbrs()
		{
			for (auto& block : blocks)
			{
				for (auto& inst : block)
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
	};

	

	// Rewrite JMP_RELBR and COND_BR
	template<addr_width::type Addr_width = addr_width::x64>
	struct inst_block_t
	{
		inst_list_t<Addr_width> instructions;
		uint64_t start;
		uint64_t end;
		explicit inst_block_t()
		{
			start = end = 0;
		}
	};

	template<addr_width::type Addr_width = addr_width::x64>
	class inst_routine_t
	{
	public:
		uint64_t range_start = 0;
		uint64_t range_end = 0;

		uint64_t entry_rva = 0;

		bool valid_disassembly = true;

		// move these decode functions into the decode_thread structure. which will now create
		// routine_t structures
		//

	};

	template<addr_width::type Addr_width = addr_width::x64>
	class dasm_thread_t
	{
		// Temp data for decoding.
		//
		std::list<inst_block_t<Addr_width> > m_blocks;

		// If this function starts in an seh block(RUNTIME_FUNCTION), it is described here
		// However functions, as we see in dxgkrnl.sys, can be scattered about and have
		// multiple blocks in different places. Thus having multiple RUNTIME_FUNCTION
		// entries. So we must treat the bounds specified in RUNTIME_FUNCTION as weak bounds
		// that can be steped outside of if deemed necessary.
		//
		uint64_t e_range_start;
		uint64_t e_range_end;

		pex::image_runtime_function_it_t e_runtime_func;

		// Unwind info rva.
		uint64_t e_unwind_info;


		std::thread* m_thread;

		std::atomic_bool m_signal_start;
		std::atomic_bool m_signal_shutdown;

		std::mutex m_queued_routines_lock;
		std::vector<uint64_t> m_queued_routines;

		decoder_context_t<Addr_width>* m_decoder_context;

		decode_lookup_table m_lookup_table;
	public:
		inline static std::atomic_uint32_t queued_routine_count;

		// The list of completed routines to be merged at the end
		//
		std::list<routine_t<Addr_width> > completed_routines;

		// The number of times we stopped decoding a block => function because of an unhandled
		// instruction. Want to get this number as low as possible :)
		//
		uint32_t invalid_routine_count;

		explicit dasm_thread_t(decoder_context_t<Addr_width>* context)
			: m_decoder_context(context),
			m_signal_start(false),
			m_signal_shutdown(false),
			m_lookup_table(m_decoder_context->raw_data_size),
			e_runtime_func(nullptr)
		{
			m_thread = new std::thread(&dasm_thread_t::run, this);
		}
		explicit dasm_thread_t(dasm_thread_t const& to_copy)
			: m_lookup_table(to_copy.m_decoder_context->raw_data_size),
			e_runtime_func(to_copy.e_runtime_func.get())
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
					decode(routine_rva);
					m_lookup_table.clear();
					m_blocks.clear();
					--queued_routine_count;
					continue; //Skip the sleep.
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		}

		bool decode_block(uint64_t rva)
		{
			auto& current_block = m_blocks.emplace_back();

			while (!m_lookup_table.is_inst_start(rva))
			{
				auto& inst = current_block.instructions.emplace_back();

				int32_t ilen = inst.decode(const_cast<uint8_t*>(m_decoder_context->raw_data_start + rva), m_decoder_context->raw_data_size - rva);
				if (ilen == 0)
				{
					std::printf("Failed to decode, 0 inst length. RVA: 0x%p\n", rva);
					break;
				}

				//std::printf("IClass: %s\n", xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));

				inst.my_symbol = m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(rva);

				m_lookup_table.update_inst(rva, ilen);

				bool has_reloc = m_decoder_context->binary_interface->symbol_table->inst_uses_reloc(rva, ilen, inst.additional_data.reloc.offset_in_inst, inst.additional_data.reloc.type);

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
							inst.used_symbol = m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
								rva + ilen + xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)
							);
							inst.flags |= inst_flag::disp;
						}
						else if (XED_REG_INVALID == base_reg &&
							xed_decoded_inst_get_memory_displacement_width_bits(&inst.decoded_inst, 0) == addr_width::bits<Addr_width>::value)
						{
							if (has_reloc)
							{
								inst.used_symbol = m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
									static_cast<uint64_t>(xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)) -
									m_decoder_context->binary_interface->optional_header.get_image_base()
								);
								inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
								inst.flags |= inst_flag::reloc_disp;
							}
						}
					}
					else if (has_reloc && XED_OPERAND_IMM0 == operand_name &&
						xed_decoded_inst_get_immediate_width_bits(&inst.decoded_inst) == addr_width::bits<Addr_width>::value)
					{
						inst.used_symbol = m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
							xed_decoded_inst_get_unsigned_immediate(&inst.decoded_inst) -
							m_decoder_context->binary_interface->optional_header.get_image_base()
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

					if (!m_decoder_context->validate_rva(taken_rva))
					{
						std::printf("Conditional branch to invalid rva.\n");
						goto ExitInstDecodeLoop;
					}

					inst.used_symbol = m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(taken_rva);
					inst.flags |= inst_flag::rel_br;

					//REWRITE LOGIC
					if (!m_lookup_table.is_inst_start(taken_rva))
					{
						if (!decode_block(taken_rva))
							return false;
					}
				}
				else if (cat == XED_CATEGORY_UNCOND_BR)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_JMP_GPRv:
						// Jump table.
						//
						std::printf("Unhandled inst[%08X]: XED_IFORM_JMP_GPRv.\n", rva - ilen);
						goto ExitInstDecodeLoop;
					case XED_IFORM_JMP_MEMv:
						if (!inst.used_symbol)
						{
							std::printf("Unhandled inst[%08X]: XED_IFORM_JMP_MEMv.\n", rva - ilen);
						}
						goto ExitInstDecodeLoop;
					case XED_IFORM_JMP_RELBRb:
					case XED_IFORM_JMP_RELBRd:
					case XED_IFORM_JMP_RELBRz:
					{
						int32_t jmp_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
						uint64_t dest_rva = rva + jmp_disp;

						if (!m_decoder_context->validate_rva(dest_rva))
						{
							std::printf("Unconditional branch to invalid rva.\n");
							goto ExitInstDecodeLoop;
						}
						inst.used_symbol = m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= inst_flag::rel_br;


						// REWRITE ME
						if (!m_lookup_table.is_inst_start(dest_rva))
						{
							//if (rva_in_function(dest_rva))
							if (!decode_block(dest_rva))
								return false;
							//else
							//	m_decoder_context->report_routine_rva(dest_rva); // This is most likely an optimized jmp to a function at end of current function
						}

						goto ExitInstDecodeLoop;
					}
					case XED_IFORM_JMP_FAR_MEMp2:
					case XED_IFORM_JMP_FAR_PTRp_IMMw:
						std::printf("Unhandled inst[%08X]: JMP_FAR_MEM/PTR.\n", rva - ilen);
						goto ExitInstDecodeLoop;
					}
				}
				else if (cat == XED_CATEGORY_CALL && m_decoder_context->settings.recurse_calls)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_CALL_NEAR_GPRv:
						// Call table?!
						//
						std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_GPRv.\n", rva - ilen);
						break;
					case XED_IFORM_CALL_NEAR_MEMv:
						// Import or call to absolute address...
						//
						if (!inst.used_symbol)
						{
							std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_MEMv.\n", rva - ilen);
						}
						break;

					case XED_IFORM_CALL_NEAR_RELBRd:
					case XED_IFORM_CALL_NEAR_RELBRz:
					{
						int32_t call_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
						uint64_t dest_rva = rva + call_disp;
						if (!m_decoder_context->validate_rva(dest_rva))
						{
							std::printf("Call to invalid rva.\n");
							goto ExitInstDecodeLoop;
						}

						//std::printf("Found call at 0x%X, 0x%X\n", rva - ilen, dest_rva);

						inst.used_symbol = m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= inst_flag::rel_br;

						if (!m_lookup_table.is_self(dest_rva))
						{
							m_decoder_context->report_routine_rva(dest_rva);
						}
						break;
					}
					case XED_IFORM_CALL_FAR_MEMp2:
					case XED_IFORM_CALL_FAR_PTRp_IMMw:
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
			return true;
		}
		void decode(uint64_t rva)
		{
			if (!m_decoder_context->validate_rva(rva))
			{
				std::printf("Attempting to decode routine at invalid rva.\n");
				return;
			}

			pex::image_runtime_function_it_t runtime_func(nullptr);
			if (m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_for_rva(rva).has_func_data())
			{
				runtime_func.set(m_decoder_context->binary_interface->mapped_image +
					m_decoder_context->binary_interface->symbol_table->get_func_data(rva).runtime_function_rva);
			}
			else
			{

			}

			if (!decode_block(rva))
				return;

			auto& routine = completed_routines.emplace_back();

			routine.range_start = m_decoder_context->binary_interface->symbol_table->get_symbol(m_blocks.front().instructions.front().my_symbol).address;
			routine.range_end = m_decoder_context->binary_interface->symbol_table->get_symbol(m_blocks.back().instructions.back().my_symbol).address + m_blocks.back().instructions.back().length();
			routine.original_entry_rva = rva;
			routine.entry_symbols.push_back(m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(rva));

			for (auto& block : m_blocks)
			{
				auto& new_block = routine.blocks.emplace_back();
				new_block.splice(new_block.end(), block.instructions);
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

		std::list<routine_t<Addr_width> > completed_routines;

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
				completed_routines.splice(completed_routines.end(), thread.completed_routines);
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

