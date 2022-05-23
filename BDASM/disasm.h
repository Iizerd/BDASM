//#pragma once
//
//#include <initializer_list>
//#include <list>
//#include <functional>
//#include <atomic>
//#include <mutex>
//#include <Windows.h>
//
//#include "addr_width.h"
//#include "inst.h"
//#include "symbol.h"
//
//template<address_width Addr_width = address_width::x64>
//class x86_dasm_t;
//
//// This just makes things easier... holy shit enum class so close to being useful,,, but then just isnt.
//namespace lookup_table_entry
//{
//	typedef uint8_t type;
//
//	constexpr uint8_t none = 0;
//
//	// Is the start of an instruction
//	// 
//	constexpr uint8_t is_inst_start = (1 << 0);
//
//	// Is this address inside a decoded inst.
//	// 
//	constexpr uint8_t is_decoded = (1 << 1);
//
//	// This is to prevent recursive routines messing stuff up
//	//
//	constexpr uint8_t is_self = (1 << 2);
//}
//
//
//template<address_width Addr_width = address_width::x64>
//class inst_block_t
//{
//public:
//	uint64_t start;
//	uint64_t end;
//
//	std::list<inst_t<Addr_width> > instructions;
//
//	explicit inst_block_t()
//		: start(0), end(0)
//	{}
//	explicit inst_block_t(inst_block_t const& to_copy)
//		: start(0), end(0)
//	{
//		instructions.insert(instructions.begin(), to_copy.instructions.begin(), to_copy.instructions.end());
//	}
//	void print_block() const
//	{
//		for (auto const& inst : instructions)
//		{
//			inst.print_details();
//		}
//	}
//};
//
//template <address_width Addr_width = address_width::x64>
//struct routine_t
//{
//public:
//	std::list<inst_block_t<Addr_width> > blocks;
//
//	void print_blocks()
//	{
//		uint32_t i = 0;
//		for (auto const& block : blocks)
//		{
//			std::printf("Block[%u] %p %p\n", i++, block.start, block.end);
//			block.print_block();
//		}
//	}
//	uint32_t count_instructions()
//	{
//		uint32_t total = 0;
//		for (auto const& block : blocks)
//			total += block.instructions.size();
//		return total;
//	}
//};
//
//
//class decode_lookup_table
//{
//	const uint64_t m_table_size;
//	lookup_table_entry::type* m_entries;
//public:
//	explicit decode_lookup_table(uint64_t table_size)
//		: m_table_size(table_size)
//	{
//		m_entries = new uint8_t[table_size];
//		for (int i = 0; i < table_size; i++)
//			m_entries[i] = lookup_table_entry::none;
//	}
//	~decode_lookup_table()
//	{
//		delete[] m_entries;
//	}
//	finline void clear()
//	{
//		for (int i = 0; i < m_table_size; i++)
//			m_entries[i] = lookup_table_entry::none;
//	}
//	finline bool is_self(uint64_t rva) const
//	{
//		return static_cast<bool>(m_entries[rva] & lookup_table_entry::is_self);
//	}
//	finline bool is_decoded(uint64_t rva) const
//	{
//		return static_cast<bool>(m_entries[rva] & lookup_table_entry::is_decoded);
//	}
//	finline bool is_inst_start(uint64_t rva) const
//	{
//		return static_cast<bool>(m_entries[rva] & lookup_table_entry::is_inst_start);
//	}
//	finline void update_inst(uint64_t rva, int32_t inst_len)
//	{
//		m_entries[rva] |= lookup_table_entry::is_inst_start;
//		for (int32_t i = 0; i < inst_len; i++)
//			m_entries[rva + i] |= lookup_table_entry::is_decoded;
//	}
//};
//
//template<address_width Addr_width = address_width::x64>
//class decode_thread_t
//{
//	std::mutex m_rvas_lock;
//	std::vector<uint64_t> m_rvas;
//	x86_dasm_t<Addr_width>* m_dasm;
//	std::atomic_bool m_signal_exit;
//	std::atomic_bool m_signal_start;
//	std::atomic_uint32_t& m_rva_counter;
//	std::thread* m_thread;
//public:
//
//	std::list<routine_t<Addr_width> > finished_routines;
//
//	explicit decode_thread_t(x86_dasm_t<Addr_width>* dasm, std::atomic_uint32_t& rva_counter)
//		:
//		m_dasm(dasm),
//		m_signal_exit(false),
//		m_signal_start(false),
//		m_rva_counter(rva_counter)
//	{ 
//		m_thread = new std::thread(&decode_thread_t::run, this);
//		m_thread->detach();
//	}
//	explicit decode_thread_t(decode_thread_t<Addr_width> const& to_copy)
//		: m_rva_counter(to_copy.m_rva_counter)
//	{
//		printf("Copy consturctor called. This is bad\n");
//	}
//	~decode_thread_t()
//	{
//		m_signal_exit = true;
//		// Hmm.... This seems wrong? The thread SHOULD be joinable per the standard...
//		//
//		if (m_thread->joinable())
//			m_thread->join();
//		delete m_thread;
//	}
//
//	void add_routine_rva(uint64_t offset)
//	{
//		std::lock_guard g(m_rvas_lock);
//		m_rvas.push_back(offset);
//	}
//
//	finline void signal_start()
//	{
//		m_signal_start = true;
//	}
//
//	finline bool pop_rva(uint64_t& rva)
//	{
//		if (!m_signal_start)
//			return false;
//
//		std::lock_guard g(m_rvas_lock);
//		if (m_rvas.size())
//		{
//			rva = m_rvas.back();
//			m_rvas.pop_back();
//			return true;
//		}
//		return false;
//	}
//
//	void run()
//	{
//		while (!m_signal_exit)
//		{
//			uint64_t rva = 0;
//
//			if (pop_rva(rva))
//			{
//				m_dasm->do_routine(finished_routines, rva);
//				--m_rva_counter;
//				continue; 	//Skip the sleep.
//			}
//			std::this_thread::sleep_for(std::chrono::milliseconds(1));
//		}
//	}
//};
//
//template<address_width Addr_width = address_width::x64>
//class decode_thread_manager_t
//{
//	std::vector<decode_thread_t<Addr_width> > m_threads;
//
//	// Used to equally distribute RVAs to threads
//	//
//	uint8_t m_next_thread;
//
//	uint8_t m_thread_count;
//
//	// The remaining RVAs that need to be or are being processed.
//	// 0 when all is done
//	//
//	std::atomic_uint32_t m_rva_count;
//public:
//	friend class x86_dasm_t<Addr_width>;
//	decode_thread_manager_t(x86_dasm_t<Addr_width>* dasm)
//		:
//		m_thread_count(dasm->m_max_thread_count),
//		m_next_thread(0),
//		m_rva_count(0)
//	{
//		// Prevent reallocaiton and copy constructors... 
//		//
//		m_threads.reserve(m_thread_count * 2);
//
//		for (uint8_t i = 0; i < m_thread_count; i++)
//		{
//			m_threads.emplace_back(dasm, m_rva_count);
//		}
//	}
//	finline void add_routine_rva(uint64_t rva)
//	{
//		++m_rva_count;
//
//		//printf("adding routine to %u, %u\n", m_next_thread, m_thread_count);
//		m_threads[m_next_thread].add_routine_rva(rva);
//
//		m_next_thread++;
//		if (m_next_thread >= m_thread_count)
//			m_next_thread = 0;
//	}
//	void add_routine_rvas(std::vector<uint64_t> const& rvas)
//	{
//		for (uint64_t rva : rvas)
//			add_routine_rva(rva);
//	}
//	finline void begin()
//	{
//		for (auto& thread : m_threads)
//			thread.signal_start();
//	}
//
//	void wait_for_completion()
//	{
//		while (m_rva_count)
//		{
//			std::this_thread::sleep_for(std::chrono::milliseconds(1));
//		}
//	}
//	void splice_to_single_list(std::list<routine_t<Addr_width> >& list)
//	{
//		for (uint8_t i = 0; i < m_thread_count; i++)
//			list.splice(list.end(), m_threads[i].finished_routines);
//			
//	}
//};
//
//
//
//using dasm_routine_progress_callback = std::function<void(uint32_t)>;
//
//template<address_width Addr_width = address_width::x64>
//using dasm_block_progress_callback = std::function<void(inst_block_t<Addr_width> const&)>;
//
//
//template<address_width Addr_width>
//class x86_dasm_t
//{
//	std::atomic_bool* m_routine_lookup_table;
//
//	std::mutex m_symbol_table_lock;
//	symbol_table_t* m_symbol_table;
//
//	// Only valid while decoding
//	//
//	decode_thread_manager_t<Addr_width>* m_thread_manager;
//
//	// Settings for the disasmbla
//	//
//	// Disassembler will not recursively follow calls to disassemble all routines
//	//
//	bool m_recurse_calls;
//	
//	// Some functions might have blocks that appear before the the actual start of the function.
//	// If this happens, the decode lookup table must support this.
//	//
//	bool m_malformed_functions;
//
//	// The number of threads that can be used.
//	//
//	uint8_t m_max_thread_count;
//
//	// These are just some basic notify routines for when blocks and functions are done
//	//
//	dasm_routine_progress_callback m_routine_progress_callback;
//	dasm_block_progress_callback<Addr_width> m_block_progress_callback;
//
//	//Decoder uses this because recursion of the functions runs us out of stach space.
//	//
//	std::vector<uint64_t> m_routine_rvas;
//public:
//	friend class decode_thread_manager_t<Addr_width>;
//
//	const uint8_t* raw_data_start;
//	const uint8_t* raw_data_end;
//	const uint64_t raw_data_size;
//	const uint64_t base_adjustment;
//
//	std::list<routine_t<Addr_width> > finished_routines;
//
//	explicit x86_dasm_t(
//		uint8_t* base,
//		uint32_t size,
//		symbol_table_t* symbol_table,
//
//		// This is how we adjust relocs
//		//
//		uint64_t base_ajustment = 0
//	)
//		: raw_data_start(base),
//		raw_data_end(base + size),
//		raw_data_size(size),
//		base_adjustment(base_adjustment),
//		m_symbol_table(symbol_table),
//		m_thread_manager(nullptr),
//		m_recurse_calls(false),
//		m_malformed_functions(false),
//		m_max_thread_count(1),
//		m_routine_progress_callback(nullptr),
//		m_block_progress_callback(nullptr)
//	{
//		m_routine_lookup_table = new std::atomic_bool[size];
//		for (uint32_t i = 0; i < size; i++)
//			m_routine_lookup_table[i] = false;
//	}
//	~x86_dasm_t()
//	{
//		delete[] m_routine_lookup_table;
//	}
//
//	finline bool validate_rva(uint64_t rva)
//	{
//		return (rva < raw_data_size);
//	}
//
//	finline void set_recurse_calls(bool state)
//	{
//		m_recurse_calls = state;
//	}
//	finline bool get_recurse_calls() const
//	{
//		return m_recurse_calls;
//	}
//	finline void set_malformed_functions(bool state)
//	{
//		m_malformed_functions = state;
//	}
//	finline bool get_malformed_functions() const
//	{
//		return m_malformed_functions;
//	}
//	finline void set_max_thread_count(uint8_t thread_count)
//	{
//		m_max_thread_count = thread_count;
//	}
//	finline bool get_max_thread_count() const
//	{
//		return m_max_thread_count;
//	}
//
//	finline void set_routine_progress_callback(dasm_routine_progress_callback callback)
//	{
//		m_routine_progress_callback = callback;
//	}
//	finline void set_block_progress_callback(dasm_block_progress_callback<Addr_width> callback)
//	{
//		m_block_progress_callback = callback;
//	}
//	finline void set_routine_pointers(std::vector<uint64_t> const& rvas)
//	{
//		m_routine_rvas.clear();
//		m_routine_rvas.insert(m_routine_rvas.end(), rvas.begin(), rvas.end());
//	}
//
//	void do_block(routine_t<Addr_width>& routine, uint64_t rva, decode_lookup_table* lookup_table)
//	{
//		auto& current_block = routine.blocks.emplace_back();
//		current_block.start = rva;
//
//		auto current_block_it = std::prev(routine.blocks.end());
//
//		while (!lookup_table->is_inst_start(rva))
//		{
//			auto& inst = current_block.instructions.emplace_back();
//
//			int32_t len = inst.decode(const_cast<uint8_t*>(this->raw_data_start + rva), this->raw_data_size - rva);
//			if (!len)
//			{
//				std::printf("Failed to decode for whatever reason.\n");
//				break;
//			}
//
//			m_symbol_table_lock.lock();
//			inst.my_symbol = m_symbol_table->get_symbol_index_for_rva(symbol_flag::base, rva);
//			m_symbol_table_lock.unlock();
//
//			lookup_table->update_inst(rva, len);
//
//			rva += len;
//
//			auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
//			auto iform = xed_decoded_inst_get_iform_enum(&inst.decoded_inst);
//			//printf("cat = %s\n", xed_category_enum_t2str(cat));
//			if (cat == XED_CATEGORY_COND_BR)
//			{
//				int32_t br_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
//				uint64_t taken_rva = rva + br_disp;
//
//				if (!validate_rva(taken_rva))
//				{
//					std::printf("Unconditional jump displacement takes ip out of code section.\n");
//					goto DisassemblyLoopBreak;
//				}
//
//				// Set the symbol that this instruction obviuosly relies on.
//				//
//				m_symbol_table_lock.lock();
//				inst.used_symbol = m_symbol_table->get_symbol_index_for_rva(symbol_flag::base, static_cast<uint32_t>(taken_rva));
//				m_symbol_table_lock.unlock();
//
//				if (!lookup_table->is_inst_start(taken_rva))
//				{
//					do_block(routine, taken_rva, lookup_table);
//				}
//			}
//			else if (cat == XED_CATEGORY_UNCOND_BR)
//			{
//				// Is the compiler smart enough to create a jump table with these? (iform - XED_IFORM_CALL_NEAR_GPRv) == 0
//				// Check in ida and make sure it is. Can it be coerced if i do this ^^^^ myself?
//				//
//				switch (iform)
//				{
//				case XED_IFORM_JMP_GPRv:
//					// Look for jump table...
//					//
//					break;
//				case XED_IFORM_JMP_MEMv:
//				{
//					// Probably a jmp to an import...
//					//
//					uint64_t absloc = xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0);
//					absloc -= base_adjustment;
//
//					if (!validate_rva(absloc))
//					{
//						std::printf("Memory jmp takes ip out of code section.\n");
//						goto DisassemblyLoopBreak;
//					}
//
//					// Assign the symbol so we know where this location will be once final binary.
//					//
//					m_symbol_table_lock.lock();
//					inst.my_symbol = m_symbol_table->get_symbol_index_for_rva(symbol_flag::base, absloc);
//					m_symbol_table_lock.unlock();
//
//					break;
//				}
//				case XED_IFORM_JMP_RELBRb:
//				case XED_IFORM_JMP_RELBRd:
//				case XED_IFORM_JMP_RELBRz:
//				{
//					int32_t jmp_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
//					uint64_t dest_rva = rva + jmp_disp;
//
//					if (!validate_rva(dest_rva))
//					{
//						std::printf("Unconditional jump displacement takes ip out of code section.\n");
//						goto DisassemblyLoopBreak;
//					}
//
//					// Set the symbol that this instruction obviuosly relies on.
//					//
//					m_symbol_table_lock.lock();
//					inst.used_symbol = m_symbol_table->get_symbol_index_for_rva(symbol_flag::base, static_cast<uint32_t>(dest_rva));
//					m_symbol_table_lock.unlock();
//
//					if (!lookup_table->is_inst_start(dest_rva))
//					{
//						do_block(routine, dest_rva, lookup_table);
//					}
//					break;
//				}
//				}
//				goto DisassemblyLoopBreak;
//			}
//			else if (cat == XED_CATEGORY_CALL)
//			{
//				switch (iform)
//				{
//				case XED_IFORM_CALL_NEAR_GPRv:
//					// Don't know how to handle this.
//					//
//					break;
//
//				case XED_IFORM_CALL_NEAR_MEMv:
//				{
//					// Import.
//					//
//					uint64_t absloc = xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0);
//					absloc -= base_adjustment;
//
//					if (!validate_rva(absloc))
//					{
//						std::printf("Memory jmp takes ip out of code section.\n");
//						goto DisassemblyLoopBreak;
//					}
//
//					m_symbol_table_lock.lock();
//					inst.my_symbol = m_symbol_table->get_symbol_index_for_rva(symbol_flag::base, absloc);
//					m_symbol_table_lock.unlock();
//
//					break;
//				}
//				case XED_IFORM_CALL_NEAR_RELBRd:
//				case XED_IFORM_CALL_NEAR_RELBRz:
//					if (m_recurse_calls)
//					{
//						int32_t call_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
//						uint64_t dest_rva = rva + call_disp;
//
//						if (!validate_rva(dest_rva))
//						{
//							std::printf("Call displacement takes ip out of code section: %d %llu %llu\n", call_disp, rva, raw_data_size);
//							goto DisassemblyLoopBreak;
//						}
//
//						// Set the symbol that this instruction obviuosly relies on.
//						//
//						m_symbol_table_lock.lock();
//						inst.used_symbol = m_symbol_table->get_symbol_index_for_rva(symbol_flag::base, static_cast<uint32_t>(dest_rva));
//						m_symbol_table_lock.unlock();
//
//						if (!lookup_table->is_self(dest_rva) && !m_routine_lookup_table[dest_rva])
//						{
//							m_thread_manager->add_routine_rva(dest_rva);
//							//m_routine_rvas.push_back(dest_rva);
//
//							// Cant do this because we will quickly run out of stack space in large binaries...
//							//
//							//do_routine(dest_rva);
//						}
//					}
//					break;
//				default:
//					goto DisassemblyLoopBreak;
//				}
//			}
//			else if (cat == XED_CATEGORY_RET)
//			{
//				break;
//			}
//		}
//
//	DisassemblyLoopBreak:
//
//		current_block.end = rva;
//
//		if (m_block_progress_callback)
//			m_block_progress_callback(current_block);
//
//		// If we get here, we got to the end of a block, and the one that follows can be merged into this one if they are right next to one another.
//		// 
//		for (auto it = routine.blocks.begin(); it != routine.blocks.end(); ++it)
//		{
//			if (it->start == rva && it != current_block_it)
//			{
//				// Prepend every inst from the this finished block onto another potentially unfinished one
//				// 
//				it->instructions.splice(it->instructions.begin(), current_block.instructions);
//				it->start = current_block.start;
//				routine.blocks.erase(current_block_it);
//			}
//		}
//	}
//
//	void do_routine(std::list<routine_t<Addr_width> >& routine_list, uint64_t rva)
//	{
//		if (!validate_rva(rva) || m_routine_lookup_table[rva])
//		{
//			return;
//		}
//
//		m_routine_lookup_table[rva] = true;
//		routine_list.emplace_back();
//		auto current_routine_it = std::prev(routine_list.end());
//
//		// Start the recursion
//		//
//		decode_lookup_table lookup_table(raw_data_size);
//		do_block(routine_list.back(), rva, &lookup_table);
//
//		current_routine_it->blocks.sort([](inst_block_t<Addr_width> const& b1, inst_block_t<Addr_width> const& b2) -> bool
//			{
//				return (b1.start < b2.start);
//			});
//
//		for (auto it = current_routine_it->blocks.begin(); it != current_routine_it->blocks.end(); ++it)
//		{
//			auto next = std::next(it);
//			if (next == current_routine_it->blocks.end())
//				break;
//
//			if (it->end == next->start)
//			{
//				it->instructions.splice(it->instructions.end(), next->instructions);
//
//				current_routine_it->blocks.erase(next);
//			}
//		}
//
//		if (m_routine_progress_callback)
//			m_routine_progress_callback(current_routine_it->count_instructions());
//
//	}
//
//
//	void go()
//	{
//		m_thread_manager = new decode_thread_manager_t<Addr_width>(this);
//
//		m_thread_manager->add_routine_rvas(m_routine_rvas);
//
//		m_thread_manager->begin();
//
//		m_thread_manager->wait_for_completion();
//
//		m_thread_manager->splice_to_single_list(finished_routines);
//
//		delete m_thread_manager;
//	}
//};
//
//
//
//
//
