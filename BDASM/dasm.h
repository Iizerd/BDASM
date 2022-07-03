


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

		std::atomic_bool* routine_table;

		std::atomic_bool* relbr_table;

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

	// This just makes things easier... holy shit enum class so close to being useful,,, but then just isnt.
	namespace lookup_table_flag
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
	class decode_lookup_table
	{
		const uint64_t m_table_size;
		lookup_table_flag::type* m_entries;
		std::vector<uint32_t> m_clear_indices;
	public:
		explicit decode_lookup_table(uint64_t table_size)
			: m_table_size(table_size)
		{
			m_entries = (lookup_table_flag::type*)calloc(table_size, 1);
			m_clear_indices.reserve(table_size / 10);
		}
		~decode_lookup_table()
		{
			free(m_entries);
		}
		finline void clear()
		{
			for (auto i : m_clear_indices)
				m_entries[i] = lookup_table_flag::none;

			m_clear_indices.clear();
		}
		finline bool is_self(uint64_t rva) const
		{
			return static_cast<bool>(m_entries[rva] & lookup_table_flag::is_self);
		}
		finline bool is_decoded(uint64_t rva) const
		{
			return static_cast<bool>(m_entries[rva] & lookup_table_flag::is_decoded);
		}
		finline bool is_inst_start(uint64_t rva) const
		{
			return static_cast<bool>(m_entries[rva] & lookup_table_flag::is_inst_start);
		}
		finline void update_inst(uint64_t rva, int32_t inst_len)
		{
			m_entries[rva] |= lookup_table_flag::is_inst_start;
			m_clear_indices.push_back(rva);
			for (int32_t i = 0; i < inst_len; i++)
			{
				m_entries[rva + i] |= lookup_table_flag::is_decoded;
				m_clear_indices.push_back(rva + i);
			}
		}
	};
	
	template<addr_width::type Addr_width = addr_width::x64>
	class block_t
	{
	public:
		// These are set in the disassembly process and represent the start and end rvas
		// where the block was originally placed in the binary
		//
		uint32_t rva_start;
		uint32_t rva_end;

		// 
		//
		inst_list_t<Addr_width> instructions;

		// if != routine_t::blocks.end() then this block does not end in a terminating
		// instruction and must be encoded before its fallthrough block OR with a jump
		// at the end
		//
		std::list<block_t<Addr_width> >::iterator fallthrough_block;
		
		// If there is a jcc or uncond branch, this is the block it jumps to
		//
		std::list<block_t<Addr_width> >::iterator taken_block;

		// Once we finish decoding everything, we run a pass over every finished routine
		// and set this equal to the symbol(rva) of the first instruction inside of the
		// block. We then assign an arbitrary symbol to the instruction. This makes it
		// so that all the relbrs now rely on symbols set by BLOCKS, not by instructions.
		// Any passes over these blocks that might edit instructions, no longer needs to
		// update the symbol of the instructions...
		//
		uint32_t symbol;

		enum class termination_type_t : uint8_t
		{
			invalid,
			returns,
			unconditional_br,
			conditional_br,
			fallthrough,
		} termination_type;


		explicit block_t()
			: rva_start(0),
			rva_end(0),
			symbol(0),
			termination_type(termination_type_t::invalid)
		{}
		block_t(block_t const& to_copy)
			: rva_start(to_copy.rva_start)
			, rva_end(to_copy.rva_end)
			, fallthrough_block(to_copy.fallthrough_block)
			, symbol(to_copy.symbol)
			, termination_type(to_copy.termination_type)
		{
			instructions.insert(instructions.end(), to_copy.instructions.begin(), to_copy.instructions.end());
		}
		block_t(block_t&& to_move)
			: rva_start(to_move.rva_start)
			, rva_end(to_move.rva_end)
			, fallthrough_block(to_move.fallthrough_block)
			, symbol(to_move.symbol)
			, termination_type(to_move.termination_type)
		{
			instructions.splice(instructions.end(), to_move.instructions);
		}
		block_t& operator=(block_t&& to_move)
		{
			rva_start = to_move.rva_start;
			rva_end = to_move.rva_end;
			fallthrough_block = to_move.fallthrough_block;
			symbol = to_move.symbol;
			termination_type = to_move.termination_type;
			instructions.splice(instructions.end(), to_move.instructions);
			return *this;
		}

	};

	// TODO: Write control flow following iterators
	//
	template<addr_width::type Addr_width = addr_width::x64>
	class routine_t
	{
	public:

		//template<addr_width::type Addr_width = addr_width::x64>
		/*class iterator
		{
			using iterator_category = std::bidirectional_iterator_tag;
			using difference_type = std::ptrdiff_t;
			using value_type = inst_t<Addr_width>;
			using pointer = inst_t<Addr_width>*;
			using reference = inst_t<Addr_width>&;

			using my_type = iterator;
			using list_it_type = std::list<inst_list_t<Addr_width> >::iterator;
			using inst_it_type = inst_list_t<Addr_width>::iterator;

			list_it_type list_end;
			list_it_type list_it;
			inst_it_type inst_it;

		public:
			iterator(list_it_type lend, list_it_type ilist, inst_it_type iinst)
				: list_end(lend), list_it(ilist), inst_it(iinst)
			{}

			reference operator*() const
			{
				return *inst_it;
			}
			pointer operator->()
			{
				return &*inst_it;
			}

			my_type& operator++()
			{
				++inst_it;
				if (inst_it == list_it->end())
				{
					do
					{
						if (++list_it == list_end)
							break;
						else
							inst_it = list_it->begin();
					} while (!list_it->size());
				}
				return *this;
			}

			my_type operator++(int)
			{
				my_type tmp = *this;
				++(*this); return tmp;
			}

			my_type& operator--()
			{
				if (inst_it == list_it->begin())
				{
					while (!(--list_it)->size()) {}
					inst_it = std::prev(list_it->end());
				}
				else
				{
					--inst_it;
				}
				return *this;
			}

			my_type operator--(int)
			{
				my_type tmp = *this;
				--(*this); return tmp;
			}

			bool operator!=(my_type const& com)
			{
				return (com.list_it != list_it ||
					com.inst_it != inst_it);
			}

		};*/
		std::list<block_t<Addr_width> > blocks;

		// Rva in original binary
		uint64_t original_entry_rva;
		uint32_t entry_symbol;
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

		/*iterator begin()
		{
			for (auto it = blocks.begin(); it != blocks.end(); ++it)
				if (it->size())
					return iterator(blocks.end(), it, it->begin());
			return end();
		}
		iterator end()
		{
			return iterator(blocks.end(), blocks.end(), blocks.back().end());
		}*/
	};

	template<addr_width::type Addr_width = addr_width::x64>
	class thread_t
	{
		// Only valid while disassembling, points to the list of blocks in the routine
		//
		routine_t<Addr_width>* current_routine;

		// If this function starts in an seh block(RUNTIME_FUNCTION), it is described here
		// However functions, as we see in dxgkrnl.sys, can be scattered about and have
		// multiple blocks in different places. Thus having multiple RUNTIME_FUNCTION
		// entries. So we must treat the bounds specified in RUNTIME_FUNCTION as weak bounds
		// that can be steped outside of if deemed necessary.
		//
		uint64_t e_range_start;
		uint64_t e_range_end;
		uint64_t e_unwind_info; // rva
		pex::image_runtime_function_it_t e_runtime_func;


		std::thread* m_thread;

		std::atomic_bool m_signal_start;
		std::atomic_bool m_signal_shutdown;

		std::mutex m_queued_routines_lock;
		std::vector<uint64_t> m_queued_routines;

		decoder_context_t<Addr_width>* m_decoder_context;

		decode_lookup_table<Addr_width> m_lookup_table;
	public:
		inline static std::atomic_uint32_t queued_routine_count;

		// The list of completed routines to be merged at the end
		//
		std::list<routine_t<Addr_width> > completed_routines;

		// If we are decoding and determine that something marked as a routine is ACTUALLY a block
		//
		//std::vector<uint64_t> incorrectly_marked_routines;

		// The number of times we stopped decoding a block => function because of an unhandled
		// instruction. Want to get this number as low as possible :)
		//
		uint32_t invalid_routine_count;

		explicit thread_t(decoder_context_t<Addr_width>* context)
			: m_decoder_context(context),
			m_signal_start(false),
			m_signal_shutdown(false),
			m_lookup_table(m_decoder_context->raw_data_size),
			e_runtime_func(nullptr)
		{
			m_thread = new std::thread(&thread_t::run, this);
		}
		explicit thread_t(thread_t const& to_copy)
			: m_lookup_table(to_copy.m_decoder_context->raw_data_size),
			e_runtime_func(to_copy.e_runtime_func.get())
		{
			std::printf("Copy constructor called. This is bad.\n");
		}
		~thread_t()
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

		// Use the repair table to prune all incorrectly labeled routines.
		//
		void repair()
		{
			auto start_size = completed_routines.size();
			for (uint32_t i = 0; i < m_decoder_context->raw_data_size; ++i)
			{
				if (m_decoder_context->relbr_table[i])
				{
					completed_routines.erase(std::remove_if(completed_routines.begin(), completed_routines.end(), [i](routine_t<Addr_width> const& routine) -> bool
						{
							return (routine.original_entry_rva == static_cast<uint32_t>(i));
						}),
						completed_routines.end()
							);
				}
			}
			std::printf("Repair removed %llu routines.\n", start_size - completed_routines.size());
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
					--queued_routine_count;
					continue; //Skip the sleep.
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
		}
		
		void block_trace()
		{
			for (auto& block : current_routine->blocks)
			{
				printf("Block: %X : %X\n", block.rva_start, block.rva_end);
			}
		}

		template<typename... Args>
		void log_error(const char* format, Args... args)
		{
			std::printf("ERROR[%08X] ", static_cast<uint32_t>(current_routine->original_entry_rva));
			std::printf(format, args...);
		}

		// For when we find a relative that jumps into an existing block, we need to split that block across
		// the label and add fallthrough.
		std::list<block_t<Addr_width> >::iterator split_block(uint64_t rva)
		{
			for (auto block_it = current_routine->blocks.begin(); block_it != current_routine->blocks.end(); ++block_it)
			{
				if (rva >= block_it->rva_start && rva < block_it->rva_end)
				{
					for (auto inst_it = block_it->instructions.begin(); inst_it != block_it->instructions.end(); ++inst_it)
					{
						if (inst_it->original_rva == rva)
						{
							// Return if this shit already at the start of a block nameen?
							//
							if (inst_it == block_it->instructions.begin())
								return block_it; 

							// Otherwise, create a new block and fill it with all instructions in the current block up to rva.
							//
							auto& new_block = current_routine->blocks.emplace_front();

							new_block.rva_start = block_it->rva_start;
							new_block.rva_end = rva;
							new_block.fallthrough_block = block_it;
							new_block.termination_type = block_t<>::termination_type_t::fallthrough;
							new_block.instructions.splice(new_block.instructions.end(), block_it->instructions, block_it->instructions.begin(), inst_it);
							
							block_it->rva_start = rva;
							return block_it;
						}
					}
				}
			}
			std::printf("Failed to split block across label at %X\n", rva);
			block_trace();
			return current_routine->blocks.end();
		}
		std::list<block_t<Addr_width> >::iterator decode_block(uint64_t rva)
		{
			current_routine->blocks.emplace_front().rva_start = rva;
			auto cur_block_it = current_routine->blocks.begin();
			cur_block_it->fallthrough_block = current_routine->blocks.end();
			cur_block_it->taken_block = current_routine->blocks.end();
			cur_block_it->rva_end = m_decoder_context->raw_data_size;
			while (!m_lookup_table.is_inst_start(rva))
			{
				auto& inst = cur_block_it->instructions.emplace_back();

				int32_t ilen = inst.decode(const_cast<uint8_t*>(m_decoder_context->raw_data_start + rva), m_decoder_context->raw_data_size - rva);
				if (ilen == 0)
				{
					log_error("Failed to decode, 0 inst length. RVA: 0x%p\n", rva);
					return current_routine->blocks.end();
				}

				//std::printf("IClass: %s\n", xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));

				inst.original_rva = rva; // m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(rva);

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
							inst.used_symbol = rva + ilen + xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0);/* m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
								rva + ilen + xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)
							);*/
							inst.flags |= inst_flag::disp;
						}
						else if (XED_REG_INVALID == base_reg &&
							xed_decoded_inst_get_memory_displacement_width_bits(&inst.decoded_inst, 0) == addr_width::bits<Addr_width>::value)
						{
							if (has_reloc)
							{
								inst.used_symbol = static_cast<uint64_t>(xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)) -
									m_decoder_context->binary_interface->optional_header.get_image_base();
								/*m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
									static_cast<uint64_t>(xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)) -
									m_decoder_context->binary_interface->optional_header.get_image_base()
								);*/
								inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
								inst.flags |= inst_flag::reloc_disp;
							}
						}
					}
					else if (has_reloc && XED_OPERAND_IMM0 == operand_name &&
						xed_decoded_inst_get_immediate_width_bits(&inst.decoded_inst) == addr_width::bits<Addr_width>::value)
					{
						inst.used_symbol = xed_decoded_inst_get_unsigned_immediate(&inst.decoded_inst) -
							m_decoder_context->binary_interface->optional_header.get_image_base(); 
						/*m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(
							xed_decoded_inst_get_unsigned_immediate(&inst.decoded_inst) -
							m_decoder_context->binary_interface->optional_header.get_image_base()
						);*/
						inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
						inst.flags |= inst_flag::reloc_imm;
					}
				}

				rva += ilen;

				// Update the end of the current block so its correct if we need to call split_block
				cur_block_it->rva_end = rva;

				// Follow control flow
				//
				auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
				if (cat == XED_CATEGORY_COND_BR)
				{
					int32_t br_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
					uint64_t taken_rva = rva + br_disp;

					if (!m_decoder_context->validate_rva(taken_rva))
					{
						log_error("Conditional branch to invalid rva.\n");
						return current_routine->blocks.end();
					}

					inst.used_symbol = taken_rva; // m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(taken_rva);
					inst.flags |= inst_flag::rel_br;

					if (!m_lookup_table.is_inst_start(taken_rva))
					{
						if ((cur_block_it->taken_block = decode_block(taken_rva)) == current_routine->blocks.end())
						{
							log_error("Failed to decode a new block for conditional branch at %p\n", rva - ilen);
							return current_routine->blocks.end();
						}
					}
					else
					{
						if ((cur_block_it->taken_block = split_block(taken_rva)) == current_routine->blocks.end())
						{
							log_error("Failed to split block for conditional branch at %p\n", rva - ilen);
							return current_routine->blocks.end();
						}
					}

					m_decoder_context->relbr_table[taken_rva] = true;

					auto fallthrough = current_routine->blocks.end();
					auto itype = 0;
					if (!m_lookup_table.is_inst_start(rva))
					{
						fallthrough = decode_block(rva);
						itype = 1;
					}
					else
					{
						for (auto block_it = current_routine->blocks.begin(); block_it != current_routine->blocks.end(); ++block_it)
							if (block_it->rva_start == rva)
								fallthrough = block_it;
						itype = 2;
					}

					if (fallthrough == current_routine->blocks.end())
					{
						log_error("Error decoding fallthrough at %p %X\n", rva, itype);
						return current_routine->blocks.end();
					}

					cur_block_it->termination_type = block_t<>::termination_type_t::conditional_br;
					cur_block_it->fallthrough_block = fallthrough;

					goto ExitInstDecodeLoop;
				}
				else if (cat == XED_CATEGORY_UNCOND_BR)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_JMP_GPRv:
						// Jump table.
						//
						log_error("Unhandled inst[%08X]: XED_IFORM_JMP_GPRv.\n", rva - ilen);
						return current_routine->blocks.end();
					case XED_IFORM_JMP_MEMv:
						if (!inst.used_symbol)
						{
							log_error("Unhandled inst[%08X]: XED_IFORM_JMP_MEMv.\n", rva - ilen);
							return current_routine->blocks.end();
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
							log_error("Unconditional branch to invalid rva.\n");
							goto ExitInstDecodeLoop;
						}
						inst.used_symbol = dest_rva; // m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= inst_flag::rel_br;


						// REWRITE ME
						if (!m_lookup_table.is_inst_start(dest_rva))
						{
							// Here i will try to detect odd function calls that use a jump instead. 
							//
							//if constexpr (Addr_width == addr_width::x64)
							//{
							//	if (dest_rva < e_range_start || dest_rva >= e_range_end)
							//	{
							//		// No func data, this is a tail call to a leaf.
							//		//
							//		if (!m_decoder_context->binary_interface->symbol_table->has_func_data(dest_rva))
							//		{
							//			m_decoder_context->report_routine_rva(dest_rva);
							//			goto ExitInstDecodeLoop;
							//		}
							//		else
							//		{
							//			// Not a leaf? lets see if the unwind info is the same
							//			// If it is, this is just an oddly formed function
							//			//
							//			auto runtime_func = m_decoder_context->binary_interface->get_it<pex::image_runtime_function_it_t>(
							//				m_decoder_context->binary_interface->symbol_table->get_func_data(rva).runtime_function_rva
							//			);
							//			// This relies on the fact that multiple runtime function structures for a single func will
							//			// use the same unwind info structure, and the rvas will be the same
							//			//
							//			if (runtime_func.get_unwindw_info_address() != e_unwind_info)
							//			{
							//				m_decoder_context->report_routine_rva(dest_rva);
							//				goto ExitInstDecodeLoop;
							//			}
							//		}
							//	}
							//}

							if (decode_block(dest_rva) == current_routine->blocks.end())
							{
								log_error("Failed to decode a new block for un-conditional branch at %p\n", rva - ilen);
								return current_routine->blocks.end();
							}

						}
						else
						{
							if ((cur_block_it->taken_block = split_block(dest_rva)) == current_routine->blocks.end())
							{
								log_error("Failed to split a new block for un-conditional branch at %p\n", rva - ilen);
								return current_routine->blocks.end();
							}
						}


						m_decoder_context->relbr_table[dest_rva] = true;

						cur_block_it->termination_type = block_t<>::termination_type_t::unconditional_br;

						goto ExitInstDecodeLoop;
					}
					case XED_IFORM_JMP_FAR_MEMp2:
					case XED_IFORM_JMP_FAR_PTRp_IMMw:
						log_error("Unhandled inst[%08X]: JMP_FAR_MEM/PTR.\n", rva - ilen);
						return current_routine->blocks.end();
					}
				}
				else if (cat == XED_CATEGORY_CALL && m_decoder_context->settings.recurse_calls)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_CALL_NEAR_GPRv:
						// Call table?!
						//
						log_error("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_GPRv.\n", rva - ilen);
						return current_routine->blocks.end();
					case XED_IFORM_CALL_NEAR_MEMv:
						// Import or call to absolute address...
						//
						if (!inst.used_symbol)
						{
							log_error("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_MEMv.\n", rva - ilen);
							return current_routine->blocks.end();
						}
						break;

					case XED_IFORM_CALL_NEAR_RELBRd:
					case XED_IFORM_CALL_NEAR_RELBRz:
					{
						int32_t call_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
						uint64_t dest_rva = rva + call_disp;
						if (!m_decoder_context->validate_rva(dest_rva))
						{
							log_error("Call to invalid rva.\n");
							return current_routine->blocks.end();
						}

						//std::printf("Found call at 0x%X, 0x%X\n", rva - ilen, dest_rva);

						inst.used_symbol = dest_rva; // m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= inst_flag::rel_br;

						if (!m_lookup_table.is_self(dest_rva))
						{
							m_decoder_context->report_routine_rva(dest_rva);
						}
						break;
					}
					case XED_IFORM_CALL_FAR_MEMp2:
					case XED_IFORM_CALL_FAR_PTRp_IMMw:
						log_error("Unhandled inst[%08X]: XED_IFORM_CALL_FAR_MEM/PTR.\n", rva - ilen);
						return current_routine->blocks.end();
					}
				}
				else if (cat == XED_CATEGORY_RET)
				{
					cur_block_it->termination_type = block_t<>::termination_type_t::returns;

					break;
				}
				else if (XED_ICLASS_INT3 == xed_decoded_inst_get_iclass(&inst.decoded_inst)/* && current_block.instructions.size() > 1*/)
				{
					break;
				}
			}

			// If we make it here, we found an already decoded instruction and need to set the fallthrough
			//
			for (auto block_it = current_routine->blocks.begin(); block_it != current_routine->blocks.end(); ++block_it)
			{
				if (rva >= block_it->rva_start && rva < block_it->rva_end)
				{
					for (auto inst_it = block_it->instructions.begin(); inst_it != block_it->instructions.end(); ++inst_it)
					{
						if (inst_it->original_rva == rva)
						{
							cur_block_it->fallthrough_block = block_it;
						}
					}
				}
			}
			cur_block_it->termination_type = block_t<>::termination_type_t::fallthrough;

		ExitInstDecodeLoop:
			cur_block_it->rva_end = rva;

			return cur_block_it;
		}
		void decode(uint64_t rva)
		{
			if (!m_decoder_context->validate_rva(rva))
			{
				std::printf("Attempting to decode routine at invalid rva.\n");
				return;
			}
			if (m_decoder_context->relbr_table[rva])
			{
				//std::printf("Skipping decode on a proposed routine start that is actually just a function chunk. %X\n", rva);
				return;
			}

			// Since this is only available for x64...
			//
			if constexpr (Addr_width == addr_width::x64)
			{
				if (m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_for_rva(rva).has_func_data())
				{
					e_runtime_func.set(m_decoder_context->binary_interface->mapped_image +
						m_decoder_context->binary_interface->symbol_table->get_func_data(rva).runtime_function_rva);

					e_range_start = e_runtime_func.get_begin_address();
					e_range_end = e_runtime_func.get_end_address();
					e_unwind_info = e_runtime_func.get_unwindw_info_address();
				}
			}

			completed_routines.emplace_back();
			current_routine = &completed_routines.back();
			current_routine->original_entry_rva = rva;
			current_routine->entry_symbol = rva; // m_decoder_context->binary_interface->symbol_table->unsafe_get_symbol_index_for_rva(rva);

			if (decode_block(rva) == current_routine->blocks.end())
			{
				++invalid_routine_count;
				return;
			}

		}
	};

	template<addr_width::type Addr_width = addr_width::x64, uint8_t Thread_count = 1>
	class dasm_t
	{
		decoder_context_t<Addr_width>* m_context;

		uint8_t m_next_thread;

		std::vector<thread_t<Addr_width> > m_threads;

		std::atomic_bool* m_routine_lookup_table;

		std::atomic_bool* m_relbr_table;

	public:

		std::list<routine_t<Addr_width> > completed_routines;

		explicit dasm_t(decoder_context_t<Addr_width>* context)
			: m_next_thread(0)
		{
			m_context = context;
			m_context->report_routine_rva = std::bind(&dasm_t::add_routine, this, std::placeholders::_1);
			m_routine_lookup_table = new std::atomic_bool[m_context->raw_data_size];
			m_context->routine_table = m_routine_lookup_table;
			for (uint32_t i = 0; i < m_context->raw_data_size; i++)
				m_routine_lookup_table[i] = false;

			m_relbr_table = new std::atomic_bool[m_context->raw_data_size];
			m_context->relbr_table = m_relbr_table;
			for (uint32_t i = 0; i < m_context->raw_data_size; i++)
				m_relbr_table[i] = false;

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
			if (routine_rva && m_routine_lookup_table[routine_rva] || !m_context->binary_interface->symbol_table->is_executable(routine_rva))
			{
				//printf("failed to add routine.\n");
				return;
			}
			//printf("added routine.\n");

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
			while (thread_t<Addr_width>::queued_routine_count)
				std::this_thread::sleep_for(std::chrono::milliseconds(1));

			// Union the repair and routine tables together so we know what needs to be removed
			//
			for (uint32_t i = 0; i < m_context->raw_data_size; ++i)
			{
				m_relbr_table[i] = (m_relbr_table[i] && m_routine_lookup_table[i]);
			}

			for (auto& thread : m_threads)
			{
				// Repair could be done in parallel...
				//
				thread.repair();
				completed_routines.splice(completed_routines.end(), thread.completed_routines);
				thread.stop();
			}

			for (auto& routine : completed_routines)
			{
				for (auto& block : routine.blocks)
				{
					block.symbol = block.instructions.front().my_symbol;
					block.instructions.front().my_symbol = m_context->binary_interface->symbol_table->get_arbitrary_symbol_index();
				}
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

