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
#include "linker.h"

namespace dasm
{

	//TODO: somehow solve the problem associated with multiple functions using the same instructions
	// this becomes a problem when the original symbols are losed/not placed if for example that function
	// was virtualized...
	// this is ONLY a problem when there is a tail call, and that call leads to a function that is also
	// called elsewhere in the binary... so its a rare occurance but its still a possibility.
	// I think I can fix this by only using an rva table for function symbols, and individual arbitrary symbols
	// for control flow and instructions within that function.
	//


	namespace glt
	{
		using type = std::uint8_t;
		using Atomic_type = std::atomic<type>;
		static_assert(Atomic_type::is_always_lock_free);

		// This is a target for a routine
		//
		constexpr type is_routine = (1 << 0);

		// We know to remove functions that start at these, but are not a cal target
		// Repair if (table[func_rva] & (is_relbr_target | is_call_target) == is_relbr_target)
		//
		constexpr type is_relbr_target = (1 << 1);

		// We need to NOT remove these when doing the repair pass
		//
		constexpr type is_call_target = (1 << 2);

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

		linker_t* linker;

		//std::atomic_bool* routine_table;

		//std::atomic_bool* relbr_table;

		glt::Atomic_type* global_lookup_table;

		const uint8_t* raw_data_start;
		const uint64_t raw_data_size;
		std::function<void(uint64_t)> report_routine_rva;

		explicit decoder_context_t(pex::binary_t<Addr_width>* binary, std::function<void(uint64_t)> rva_reporter = nullptr)
			: binary_interface(binary)
			, report_routine_rva(rva_reporter)
			, raw_data_start(binary->mapped_image)
			, raw_data_size(binary->optional_header.get_size_of_image())
		{
			settings.recurse_calls = false;
		}
		explicit decoder_context_t(decoder_context_t const& to_copy)
			: binary_interface(to_copy.binary_interface)
			, report_routine_rva(to_copy.report_routine_rva)
			, raw_data_start(to_copy.raw_data_start)
			, raw_data_size(to_copy.raw_data_size)
		{
			settings.recurse_calls = to_copy.settings.recurse_calls;
		}

		bool validate_rva(uint64_t rva)
		{
			return (rva < raw_data_size);
		}
	};


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

	// Single thread lookup table used when decoding functions
	//
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

	// Termination type enums for the basic block
	//
	enum class termination_type_t : uint8_t
	{
		invalid,
		returns,
		unconditional_br,
		conditional_br,
		fallthrough,

		// An unconditional branch to something like an import
		//
		undetermined_unconditional_br,

		// This is not yet implemented, I think I need to add another member to block_t
		// A vector of block_it_t's which contains all the possible targets of the jump table
		//
		jump_table,

		// Just top if you see this. This means that the termination of the block relies
		// on some logic that cant be described generally. I see this happening when there
		// are calls to non returning functions, there is an int3 right after them.
		//
		unknown_logic,
	};

	template<addr_width::type Addr_width = addr_width::x64>
	class block_t;

	template<addr_width::type Addr_width = addr_width::x64>
	using block_it_t = std::list<block_t<Addr_width>>::iterator;

	// A basic block exactly like LLVM's
	//
	template<addr_width::type Addr_width>
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
		block_it_t<Addr_width> fallthrough_block;

		// If there is a jcc or uncond branch, this is the block it jumps to
		//
		block_it_t<Addr_width> taken_block;

		std::vector<block_it_t<Addr_width>> jump_table_blocks;

		// Once we finish decoding everything, we run a pass over every finished routine
		// and set this equal to the symbol(rva) of the first instruction inside of the
		// block. We then assign an arbitrary symbol to the instruction. This makes it
		// so that all the relbrs now rely on symbols set by BLOCKS, not by instructions.
		// Any passes over these blocks that might edit instructions, no longer needs to
		// update the symbol of the instructions...
		//
		uint32_t link;

		// This is a visited counter that comes in handy when obfuscating
		//
		uint32_t visited;

		termination_type_t termination_type;


		explicit block_t(block_it_t<Addr_width> end)
			: rva_start(0)
			, rva_end(0)
			, link(linker_t::invalid_link_value)
			, visited(0)
			, termination_type(termination_type_t::invalid)
			, fallthrough_block(end)
			, taken_block(end)
		{}
		block_t(block_t const& to_copy) = delete;
		//	: rva_start(to_copy.rva_start)
		//	, rva_end(to_copy.rva_end)
		//	, fallthrough_block(to_copy.fallthrough_block)
		//	, taken_block(to_copy.taken_block)
		//	, link(to_copy.link)
		//	, visited(to_copy.visited)
		//	, termination_type(to_copy.termination_type)
		//{
		//	instructions.insert(instructions.end(), to_copy.instructions.begin(), to_copy.instructions.end());
		//}
		block_t(block_t&& to_move)
			: rva_start(to_move.rva_start)
			, rva_end(to_move.rva_end)
			, fallthrough_block(to_move.fallthrough_block)
			, taken_block(to_move.taken_block)
			, link(to_move.link)
			, visited(to_move.visited)
			, termination_type(to_move.termination_type)
		{
			instructions.splice(instructions.end(), to_move.instructions);
		}
		block_t& operator=(block_t&& to_move)
		{
			rva_start = to_move.rva_start;
			rva_end = to_move.rva_end;
			fallthrough_block = to_move.fallthrough_block;
			taken_block = to_move.taken_block;
			link = to_move.link;
			visited = to_move.visited;
			termination_type = to_move.termination_type;
			instructions.splice(instructions.end(), to_move.instructions);
			return *this;
		}

		// This makes recursively following control flow very simple
		//
		template<typename Function, typename... Params>
		void invoke_for_next(Function func, Params... params)
		{
			switch (termination_type)
			{
			case termination_type_t::invalid: [[fallthrough]];
			case termination_type_t::returns:
				break;

			case termination_type_t::unconditional_br:
				func(taken_block, params...);
				break;

			case termination_type_t::conditional_br:
				func(taken_block, params...);
				[[fallthrough]];
			case termination_type_t::fallthrough:
				func(fallthrough_block, params...);
				break;

			case termination_type_t::jump_table: [[fallthrough]];
			case termination_type_t::undetermined_unconditional_br: [[fallthrough]];
			case termination_type_t::unknown_logic:
				break;
			}
		}

		// This one returns a boolean result, checking for false and returning after only the first
		// failure if was a conditional. RETURNS TRUE BY DEFAULT!
		//
		template<typename Function, typename... Params>
		bool invoke_for_next_check_bool(Function func, Params... params)
		{
			switch (termination_type)
			{
			case termination_type_t::invalid: [[fallthrough]];
			case termination_type_t::returns:
				break;

			case termination_type_t::unconditional_br:
				return func(taken_block, params...);
				break;

			case termination_type_t::conditional_br:
				if (!func(taken_block, params...))
					return false;
				[[fallthrough]];
			case termination_type_t::fallthrough:
				return func(fallthrough_block, params...);
				break;

			case termination_type_t::jump_table: [[fallthrough]];
			case termination_type_t::undetermined_unconditional_br: [[fallthrough]];
			case termination_type_t::unknown_logic:
				break;
			}
			return true;
		}

		uint32_t calc_byte_sizes()
		{
			uint32_t size = 0;
			for (auto& inst : instructions)
			{
				size += xed_decoded_inst_get_length(&inst.decoded_inst);
			}
			return size;
		}

		void place_in_binary(uint64_t& start_address, linker_t* linker)
		{
			linker->set_link_addr(link, start_address);
			if (link == linker_t::invalid_link_value)
			{
				printf("somehow the blocks link is zero %X %X\n", rva_start, rva_end);
			}
			for (auto& inst : instructions)
			{
				inst.redecode();
				linker->set_link_addr(inst.my_link, start_address);
				start_address += inst.length();
			}
		}

		void encode_in_binary(pex::binary_t<Addr_width>* bin, linker_t* linker, uint8_t** dest)
		{
			for (auto& inst : instructions)
			{
				*dest += inst.encode_to_binary(bin, linker, *dest);
			}
		}
	};

	namespace routine_flag
	{
		typedef uint8_t type;

		constexpr uint8_t none = 0;

		// Routine does not call other routines
		//
		constexpr uint8_t leaf = (1 << 0);

		// Routine modifies rsp in some way
		// Not currently filled
		//
		constexpr uint8_t stack_allocation = (1 << 2);


	}
	// TODO: Write control flow following iterators
	//
	template<addr_width::type Addr_width = addr_width::x64>
	class routine_t
	{
	public:

		std::list<block_t<Addr_width>> blocks;

		routine_flag::type flags;

		// This is the rva in original binary
		//
		uint32_t entry_link;

		// Iterator of the entry block
		//
		block_it_t<Addr_width> entry_block;

		routine_t()
			: flags(routine_flag::none)
			, entry_link(linker_t::invalid_link_value)
			, entry_block(blocks.end())
		{ }
		void reset_visited()
		{
			for (auto& block : blocks)
				block.visited = 0;
		}
		void reset_visited_bit(uint32_t bit)
		{
			for (auto& block : blocks)
				block.visited &= ~(1 << bit);
		}
		void promote_relbrs()
		{
			for (auto& block : blocks)
			{
				for (auto& inst : block.instructions)
				{
					auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
					if (cat == XED_CATEGORY_COND_BR)
					{
						xed_decoded_inst_set_branch_displacement_bits(&inst.decoded_inst, 0, 32);
						inst.redecode();
					}
					else if (cat == XED_CATEGORY_UNCOND_BR)
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
		void print_blocks()
		{
			for (auto& block : blocks)
			{
				std::printf("Block: %X [%X:%X]\n", block.link, block.rva_start, block.rva_end);
				for (auto& inst : block.instructions)
					std::printf("\t%08X, %08X\t%s \n", inst.my_link, inst.used_link, xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));

				switch (block.termination_type)
				{
				case termination_type_t::invalid:
					std::printf("Invalid block termination.\n\n");
					break;
				case termination_type_t::returns:
					std::printf("Block returns.\n\n");
					break;
				case termination_type_t::unconditional_br:
					std::printf("Unconditional branch: %X RVA:[%X]\n\n", block.taken_block->link, block.taken_block->rva_start);
					break;
				case termination_type_t::conditional_br:
					std::printf("Conditional Branch:\n -> Taken: %X RVA:[%X]\n -> ", block.taken_block->link, block.taken_block->rva_start);
					[[fallthrough]];
				case termination_type_t::fallthrough:
					std::printf("Fallthrough %X RVA:[%X]\n\n", block.fallthrough_block->link, block.fallthrough_block->rva_start);
					break;
				case termination_type_t::undetermined_unconditional_br:
					std::printf("Undetermined unconditional branch.\n\n");
					break;
				case termination_type_t::unknown_logic:
					std::printf("Indescribable block termination.\n\n");
					break;
				}

				/*if (block.termination_type == dasm::termination_type_t::fallthrough)
					std::printf("Fallthrough %08X [%X]\n", block.fallthrough_block->link, block.fallthrough_block->rva_start);*/

			}
		}
		void print_blocks(linker_t* linker)
		{
			for (auto& block : blocks)
			{
				std::printf("Block: %X [%X:%X]\n", block.link, block.rva_start, block.rva_end);
				for (auto& inst : block.instructions)
					std::printf("\t[%08X]: %08X, %08X\t%s \n", linker->get_link_addr(inst.my_link), inst.my_link, inst.used_link, xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));

				switch (block.termination_type)
				{
				case termination_type_t::invalid:
					std::printf("Invalid block termination.\n\n");
					break;
				case termination_type_t::returns:
					std::printf("Block returns.\n\n");
					break;
				case termination_type_t::unconditional_br:
					std::printf("Unconditional branch: %X EVAL:[%X]\n\n", block.taken_block->link, linker->get_link_addr(block.taken_block->link));
					break;
				case termination_type_t::conditional_br:
					std::printf("Conditional Branch:\n -> Taken: %X EVAL:[%X]\n -> ", block.taken_block->link, linker->get_link_addr(block.taken_block->link));
					[[fallthrough]];
				case termination_type_t::fallthrough:
					std::printf("Fallthrough %X EVAL:[%X]\n\n", block.fallthrough_block->link, linker->get_link_addr(block.fallthrough_block->link));
					break;
				case termination_type_t::undetermined_unconditional_br:
					std::printf("Undetermined unconditional branch.\n\n");
					break;
				case termination_type_t::unknown_logic:
					std::printf("Indescribable block termination.\n\n");
					break;
				}

				/*if (block.termination_type == dasm::termination_type_t::fallthrough)
					std::printf("Fallthrough %08X [%X]\n", block.fallthrough_block->link, block.fallthrough_block->rva_start);*/

			}
		}
	};

	template<addr_width::type Addr_width = addr_width::x64>
	class thread_t
	{
		std::vector<block_it_t<Addr_width>> stack;

		// Only valid while disassembling, points to the list of blocks in the routine
		//
		routine_t<Addr_width>* current_routine;

		block_it_t<Addr_width> current_block;

		//// If this function starts in an seh block(RUNTIME_FUNCTION), it is described here
		//// However functions, as we see in dxgkrnl.sys, can be scattered about and have
		//// multiple blocks in different places. Thus having multiple RUNTIME_FUNCTION
		//// entries. So we must treat the bounds specified in RUNTIME_FUNCTION as weak bounds
		//// that can be steped outside of if deemed necessary. In addition, we cant know if 
		//// there is a function start at a RUNTIME_FUNCTION's rva, or if its just another 
		//// scattered block. 
		////
		//uint64_t e_range_start;
		//uint64_t e_range_end;
		//uint64_t e_unwind_info; // rva
		//pex::image_runtime_function_it_t e_runtime_func;


		std::thread* m_thread;

		std::atomic_bool m_signal_start;
		std::atomic_bool m_signal_shutdown;

		std::mutex m_queued_routines_lock;
		std::vector<uint64_t> m_queued_routines;

		decoder_context_t<Addr_width>* m_decoder_context;

		decode_lookup_table<Addr_width> m_lookup_table;

		std::vector<uint32_t> m_link_store;
	public:
		inline static std::atomic_uint32_t queued_routine_count;

		// The list of completed routines to be merged at the end
		//
		std::list<routine_t<Addr_width>> completed_routines;

		// The number of times we stopped decoding a block => function because of an unhandled
		// instruction. Want to get this number as low as possible :)
		//
		uint32_t invalid_routine_count;

		explicit thread_t(decoder_context_t<Addr_width>* context)
			: m_decoder_context(context)
			, m_signal_start(false)
			, m_signal_shutdown(false)
			, m_lookup_table(m_decoder_context->raw_data_size)
		{
			m_thread = new std::thread(&thread_t::run, this);
			stack.clear();
		}
		explicit thread_t(thread_t const& to_copy)
			: m_lookup_table(to_copy.m_decoder_context->raw_data_size)
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

		uint32_t get_a_link()
		{
			if (!m_link_store.size())
			{
				uint32_t base = m_decoder_context->linker->get_link_bundle_base(0x1000);
				auto list = std::ranges::iota_view(base, base + 0x1000);
				m_link_store.insert(m_link_store.end(), list.begin(), list.end());
			}
			auto res = m_link_store.back();
			m_link_store.pop_back();
			return res;
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
				auto mask = (m_decoder_context->global_lookup_table[i] & (glt::is_relbr_target | glt::is_routine | glt::is_call_target));
				if (mask == (glt::is_relbr_target | glt::is_routine))
				{
					completed_routines.erase(std::remove_if(completed_routines.begin(), completed_routines.end(), [i](routine_t<Addr_width> const& routine) -> bool
						{
							return (routine.entry_link == static_cast<uint32_t>(i));
						}),
						completed_routines.end()
							);
				}
				else if (mask == (glt::is_relbr_target | glt::is_routine | glt::is_call_target))
				{
					printf("Found tail call to func at %X\n", i);
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
		finline void log_error(const char* format, Args... args)
		{
			std::printf("ERROR[%08X] ", static_cast<uint32_t>(current_routine->entry_link));
			std::printf(format, args...);
		}

		block_it_t<Addr_width> enter(uint64_t rva)
		{
			stack.push_back(current_block);
			current_routine->blocks.emplace_front(current_routine->blocks.end()).rva_start = rva;
			current_block = current_routine->blocks.begin();
			return current_block;
		}

		void leave()
		{
			auto last = stack.back();
			stack.pop_back();
			current_block = last;
		}

		block_it_t<Addr_width> error()
		{
			leave();
			return current_routine->blocks.end();
		}

		template<typename... Args>
		block_it_t<Addr_width> error(const char* format, Args... args)
		{
			log_error(format, args...);
			leave();
			return current_routine->blocks.end();
		}

		block_it_t<Addr_width> success()
		{
			auto me = current_block;
			leave();
			return me;
		}
		// For when we find a relative that jumps into an existing block, we need to split that block across
		// the label and add fallthrough.
		block_it_t<Addr_width> split_block(uint64_t rva)
		{
			for (auto block_it = current_routine->blocks.begin(); block_it != current_routine->blocks.end(); ++block_it)
			{
				if (rva >= block_it->rva_start && rva < block_it->rva_end)
				{
					for (auto inst_it = block_it->instructions.begin(); inst_it != block_it->instructions.end(); ++inst_it)
					{
						if (inst_it->original_rva == rva)
						{
							// Return if this already at the start of a block nameen?
							//
							if (inst_it == block_it->instructions.begin())
								return block_it;

							// Otherwise, create a new block and fill it with all instructions in the current block up to rva.
							//
							auto& new_block = current_routine->blocks.emplace_front(current_routine->blocks.end());
							auto new_block_it = current_routine->blocks.begin();

							new_block.rva_start = rva;
							new_block.rva_end = block_it->rva_end;
							new_block.termination_type = block_it->termination_type;
							new_block.fallthrough_block = block_it->fallthrough_block;
							new_block.taken_block = block_it->taken_block;
							new_block.instructions.splice(new_block.instructions.end(), block_it->instructions, inst_it, block_it->instructions.end());

							block_it->rva_end = rva;
							block_it->termination_type = termination_type_t::fallthrough;
							block_it->fallthrough_block = new_block_it;

							for (uint32_t i = 1; i < stack.size(); ++i)
								if (stack[i] == block_it)
									stack[i] = new_block_it;

							if (current_block == block_it)
								current_block = new_block_it;

							return new_block_it;
						}
					}
				}
			}
			std::printf("Failed to split block across label at %X\n", rva);
			block_trace();
			return current_routine->blocks.end();
		}
		block_it_t<Addr_width> decode_block(uint64_t rva)
		{
			auto entry_block = enter(rva);

			while (!m_lookup_table.is_inst_start(rva))
			{
				auto& inst = current_block->instructions.emplace_back();

				int32_t ilen = inst.decode(const_cast<uint8_t*>(m_decoder_context->raw_data_start + rva), m_decoder_context->raw_data_size - rva);
				if (ilen == 0)
				{
					return error("Failed to decode, 0 inst length. RVA: 0x%p\n", rva);
				}

				//std::printf("IClass: %s\n", xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));

				inst.original_rva = rva;
				inst.my_link = get_a_link();

				m_lookup_table.update_inst(rva, ilen);

				bool has_reloc = m_decoder_context->binary_interface->data_table->inst_uses_reloc(rva, ilen, inst.additional_data.reloc.offset_in_inst, inst.additional_data.reloc.type);

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
						if (max_reg_width<XED_REG_RIP, Addr_width>::value == base_reg)
						{
							inst.used_link = rva + ilen + xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0);
							inst.flags |= inst_flag::disp;
						}
						else if (XED_REG_INVALID == base_reg &&
							xed_decoded_inst_get_memory_displacement_width_bits(&inst.decoded_inst, 0) == addr_width::bits<Addr_width>::value)
						{
							if (has_reloc)
							{
								inst.used_link = static_cast<uint64_t>(xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)) -
									m_decoder_context->binary_interface->optional_header.get_image_base();
								inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
								inst.flags |= inst_flag::reloc_disp;
							}
						}
					}
					else if (has_reloc && XED_OPERAND_IMM0 == operand_name &&
						xed_decoded_inst_get_immediate_width_bits(&inst.decoded_inst) == addr_width::bits<Addr_width>::value)
					{
						inst.used_link = xed_decoded_inst_get_unsigned_immediate(&inst.decoded_inst) -
							m_decoder_context->binary_interface->optional_header.get_image_base();
						inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
						inst.flags |= inst_flag::reloc_imm;
					}
				}

				rva += ilen;
				// Update the end of the current block so its correct if we need to call split_block
				current_block->rva_end = rva;

				// Follow control flow
				//
				auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
				if (cat == XED_CATEGORY_COND_BR)
				{
					int32_t br_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
					uint64_t taken_rva = rva + br_disp;

					if (!m_decoder_context->validate_rva(taken_rva))
					{
						return error("Conditional branch to invalid rva.\n");
					}

					//inst.used_link = taken_rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(taken_rva);
					inst.flags |= (inst_flag::rel_br | inst_flag::block_terminator);

					if (!m_lookup_table.is_inst_start(taken_rva))
					{
						if ((current_block->taken_block = decode_block(taken_rva)) == current_routine->blocks.end())
						{
							return error("Failed to decode a new block for conditional branch at %p\n", rva - ilen);
						}
					}
					else
					{
						if ((current_block->taken_block = split_block(taken_rva)) == current_routine->blocks.end())
						{
							return error("Failed to split block for conditional branch at %p\n", rva - ilen);
						}
					}


					inst.used_link = current_block->taken_block->instructions.begin()->my_link;

					m_decoder_context->global_lookup_table[taken_rva] |= glt::is_relbr_target;

					auto fallthrough = current_routine->blocks.end();
					if (!m_lookup_table.is_inst_start(rva))
					{
						fallthrough = decode_block(rva);
					}
					else
					{
						for (auto block_it = current_routine->blocks.begin(); block_it != current_routine->blocks.end(); ++block_it)
							if (block_it->rva_start == rva)
								fallthrough = block_it;
					}

					if (fallthrough == current_routine->blocks.end())
					{
						return error("Error decoding fallthrough at %p\n", rva);
					}

					current_block->termination_type = termination_type_t::conditional_br;
					current_block->fallthrough_block = fallthrough;

					goto ExitInstDecodeLoop;
				}
				else if (cat == XED_CATEGORY_UNCOND_BR)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_JMP_GPRv:
						// Jump table.
						//
						return error("Unhandled inst at %08X XED_IFORM_JMP_GPRv.\n", rva - ilen);
					case XED_IFORM_JMP_MEMv:
						if (!inst.used_link)
						{
							return error("Unhandled inst at %08X: XED_IFORM_JMP_MEMv.\n", rva - ilen);
						}
						//return error("Unhandled inst at %08X: XED_IFORM_JMP_MEMv.\n", rva - ilen);
						current_block->termination_type = termination_type_t::undetermined_unconditional_br;
						inst.flags |= (inst_flag::block_terminator | inst_flag::routine_terminator);
						goto ExitInstDecodeLoop;
					case XED_IFORM_JMP_RELBRb:
					case XED_IFORM_JMP_RELBRd:
					case XED_IFORM_JMP_RELBRz:
					{
						int32_t jmp_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
						uint64_t dest_rva = rva + jmp_disp;

						if (!m_decoder_context->validate_rva(dest_rva))
						{
							return error("Unconditional branch to invalid rva.\n");
						}
						//inst.used_link = dest_rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= (inst_flag::rel_br | inst_flag::block_terminator);


						// REWRITE ME
						if (!m_lookup_table.is_inst_start(dest_rva))
						{
							if ((current_block->taken_block = decode_block(dest_rva)) == current_routine->blocks.end())
							{
								return error("Failed to decode a new block for un-conditional branch at %p\n", rva - ilen);
							}

						}
						else
						{
							if ((current_block->taken_block = split_block(dest_rva)) == current_routine->blocks.end())
							{
								return error("Failed to split a new block for un-conditional branch at %p\n", rva - ilen);
							}
						}

						inst.used_link = current_block->taken_block->instructions.begin()->my_link;

						//m_decoder_context->relbr_table[dest_rva] = true;
						m_decoder_context->global_lookup_table[dest_rva] |= glt::is_relbr_target;
						current_block->termination_type = termination_type_t::unconditional_br;

						goto ExitInstDecodeLoop;
					}
					case XED_IFORM_JMP_FAR_MEMp2:
					case XED_IFORM_JMP_FAR_PTRp_IMMw:
						return error("Unhandled inst at %08X: JMP_FAR_MEM/PTR.\n", rva - ilen);
					}
				}
				else if (cat == XED_CATEGORY_CALL && m_decoder_context->settings.recurse_calls)
				{
					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
					{
					case XED_IFORM_CALL_NEAR_GPRv:
						// Call table?!
						//
						return error("Unhandled inst at %08X: XED_IFORM_CALL_NEAR_GPRv.\n", rva - ilen);
					case XED_IFORM_CALL_NEAR_MEMv:
						// Import or call to absolute address...
						//
						/*if (!inst.used_link)
						{
							log_error("Unhandled inst at %08X: XED_IFORM_CALL_NEAR_MEMv.\n", rva - ilen);
							return error();
						}*/
						break;

					case XED_IFORM_CALL_NEAR_RELBRd:
					case XED_IFORM_CALL_NEAR_RELBRz:
					{
						int32_t call_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
						uint64_t dest_rva = rva + call_disp;


						if (!m_decoder_context->validate_rva(dest_rva))
						{
							return error("Call to invalid rva.\n");
						}

						//std::printf("Found call at 0x%X, 0x%X\n", rva - ilen, dest_rva);

						inst.used_link = dest_rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(dest_rva);
						inst.flags |= inst_flag::rel_br;

						if (!m_lookup_table.is_self(dest_rva))
						{
							m_decoder_context->report_routine_rva(dest_rva);
						}
						m_decoder_context->global_lookup_table[dest_rva] |= glt::is_call_target;
						break;
					}
					case XED_IFORM_CALL_FAR_MEMp2:
					case XED_IFORM_CALL_FAR_PTRp_IMMw:
						return error("Unhandled inst at %08X: XED_IFORM_CALL_FAR_MEM/PTR.\n", rva - ilen);
					}
				}
				else if (cat == XED_CATEGORY_RET)
				{
					current_block->termination_type = termination_type_t::returns;
					inst.flags |= (inst_flag::block_terminator | inst_flag::routine_terminator);
					goto ExitInstDecodeLoop;
				}
				else if (XED_ICLASS_INT3 == xed_decoded_inst_get_iclass(&inst.decoded_inst)/* && current_block.instructions.size() > 1*/)
				{
					current_block->termination_type = termination_type_t::unknown_logic;
					goto ExitInstDecodeLoop;
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
							current_block->fallthrough_block = block_it;
						}
					}
				}
			}
			current_block->termination_type = termination_type_t::fallthrough;

		ExitInstDecodeLoop:
			current_block->rva_end = rva;
			leave();
			return entry_block;
		}
		void decode(uint64_t rva)
		{
			if (!m_decoder_context->validate_rva(rva))
			{
				std::printf("Attempting to decode routine at invalid rva.\n");
				return;
			}

			auto entry_rva = rva;

			completed_routines.emplace_back();
			current_routine = &completed_routines.back();
			current_routine->entry_link = rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(rva);

			if ((current_routine->entry_block = decode_block(rva)) == current_routine->blocks.end())
			{
				completed_routines.pop_back();
				++invalid_routine_count;
				return;
			}



			for (auto block_it = current_routine->blocks.begin(); block_it != current_routine->blocks.end(); ++block_it)
			{/*
				if (block_it->rva_start == entry_rva)
					current_routine->entry_block = block_it;*/
				block_it->link = block_it->instructions.front().my_link;
				block_it->instructions.front().my_link = m_decoder_context->linker->allocate_link();
			}
		}
	};

	template<addr_width::type Addr_width = addr_width::x64, uint8_t Thread_count = 1>
	class dasm_t
	{
		decoder_context_t<Addr_width>* m_context;

		uint8_t m_next_thread;

		std::vector<thread_t<Addr_width>> m_threads;

		glt::Atomic_type* m_global_lookup_table;

	public:

		std::list<routine_t<Addr_width>> completed_routines;

		uint32_t invalid_routine_count;

		explicit dasm_t(decoder_context_t<Addr_width>* context)
			: m_next_thread(0)
			, m_context(context)
		{
			m_context->report_routine_rva = std::bind(&dasm_t::add_routine, this, std::placeholders::_1, true);

			m_global_lookup_table = new glt::Atomic_type[m_context->raw_data_size];
			for (uint32_t i = 0; i < m_context->raw_data_size; i++)
				m_global_lookup_table[i] = 0;

			m_context->global_lookup_table = m_global_lookup_table;

			m_threads.reserve(Thread_count * 2);
			for (uint8_t i = 0; i < Thread_count; ++i)
				m_threads.emplace_back(m_context);
		}
		~dasm_t()
		{
			if (m_global_lookup_table)
				delete[] m_global_lookup_table;
		}

		void add_routine(uint64_t routine_rva, bool is_call_target = false)
		{
			if (!routine_rva || (m_global_lookup_table[routine_rva] & glt::is_routine) || !m_context->binary_interface->data_table->is_executable(routine_rva))
			{
				//printf("failed to add routine.\n");
				return;
			}

			m_global_lookup_table[routine_rva] |= glt::is_routine;

			if (is_call_target)
				m_global_lookup_table[routine_rva] |= glt::is_call_target;

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

			for (auto& thread : m_threads)
			{
				// Repair could be done in parallel...
				//
				thread.repair();
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

