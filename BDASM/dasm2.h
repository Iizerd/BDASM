//#pragma once
//
//#include "addr_width.h"
//#include "inst.h"
//#include "pex.h"
//#include "size_casting.h"
//
//namespace dasm
//{
//	template<addr_width::type Addr_width = addr_width::x64>
//	struct rva_descriptor_t
//	{
//		std::list<inst_list_t<Addr_width>>::iterator block;
//
//		std::atomic_bool decoded;
//	};
//
//	template<addr_width::type Addr_width = addr_width::x64>
//	struct thread_context_t
//	{
//		pex::binary_t<Addr_width>* bin;
//
//		const uint8_t* rva_base;
//		const uint64_t rva_max;
//
//		rva_descriptor_t<Addr_width>* lookup_table;
//
//		std::function<void(uint64_t)> report_func_rva;
//
//		thread_context_t(pex::binary_t<Addr_width>* binary)
//			: rva_base(binary->mapped_image)
//			, rva_max(static_cast<uint64_t>(binary->optional_header.get_size_of_image()))
//			, bin(binary)
//		{ }
//
//		bool validate_rva(uint64_t rva)
//		{
//			return rva < rva_max;
//		}
//	};
//
//	template<addr_width::type Addr_width = addr_width::x64>
//	struct block_discovery_thread_t
//	{
//		thread_context_t<Addr_width>* m_context;
//
//		std::thread* m_thread;
//
//		std::atomic_bool m_signal_start;
//		std::atomic_bool m_signal_shutdown;
//
//		std::mutex m_queued_routines_lock;
//		std::vector<uint64_t> m_queued_routines;
//	public:
//		inline static std::atomic_uint32_t queued_routine_count;
//
//		std::vector<uint64_t> routine_starts;
//
//		std::list<inst_list_t<Addr_width>> blocks;
//
//		explicit block_discovery_thread_t(thread_context_t<Addr_width>* context)
//			: m_context(context)
//			, m_signal_start(false)
//			, m_signal_shutdown(false)
//		{
//			m_thread = new std::thread(&block_discovery_thread_t::run, this);
//		}
//		explicit block_discovery_thread_t(block_discovery_thread_t const& to_copy) = delete;
//		~block_discovery_thread_t()
//		{
//			if (m_thread->joinable())
//				m_thread->join();
//			delete m_thread;
//		}
//		bool pop_queued_routine(uint64_t& routine_rva)
//		{
//			if (!m_signal_start)
//				return false;
//
//			std::lock_guard g(m_queued_routines_lock);
//			if (m_queued_routines.size())
//			{
//				routine_rva = m_queued_routines.back();
//				m_queued_routines.pop_back();
//				return true;
//			}
//			return false;
//		}
//
//		void queue_routine(uint64_t routine_rva)
//		{
//			++queued_routine_count;
//			std::lock_guard g(m_queued_routines_lock);
//			m_queued_routines.emplace_back(routine_rva);
//		}
//
//		void start()
//		{
//			m_signal_start = true;
//		}
//		void stop()
//		{
//			m_signal_shutdown = true;
//		}
//
//		void run()
//		{
//			while (!m_signal_shutdown)
//			{
//				uint64_t routine_rva = 0;
//				if (pop_queued_routine(routine_rva))
//				{
//					decode(routine_rva);
//					--queued_routine_count;
//					continue; //Skip the sleep.
//				}
//
//				std::this_thread::sleep_for(std::chrono::milliseconds(1));
//			}
//		}
//
//		void decode_block(uint64_t rva)
//		{
//			uint64_t rva_start = rva;
//			blocks.emplace_front();
//			auto cur_block_it = blocks.begin();
//			while (!m_context->lookup_table->decoded.exchange(true))
//			{
//
//				auto& inst = cur_block_it->emplace_back();
//
//				int32_t ilen = inst.decode(const_cast<uint8_t*>(m_context->rva_base + rva), m_context->rva_max - rva);
//				if (ilen == 0)
//				{
//					std::printf("Failed to decode, 0 inst length. RVA: 0x%p\n", rva);
//					return;
//				}
//
//				if (auto iform = xed_decoded_inst_get_iform_enum(&inst.decoded_inst);
//					(iform == XED_IFORM_SUB_GPRv_IMMb ||
//					iform == XED_IFORM_SUB_GPRv_IMMz) &&
//					xed_decoded_inst_get_reg(&inst.decoded_inst, XED_OPERAND_REG0))
//					m_context->report_func_rva(rva_start);
//					
//
//				//std::printf("IClass: %s\n", xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));
//
//				inst.original_rva = rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(rva);
//
//				bool has_reloc = m_context->bin->data_table->inst_uses_reloc(rva, ilen, inst.additional_data.reloc.offset_in_inst, inst.additional_data.reloc.type);
//
//				// Parse operands for rip relative addressing and relocs
//				//
//				uint32_t num_operands = xed_decoded_inst_noperands(&inst.decoded_inst);
//				auto decoded_inst_inst = xed_decoded_inst_inst(&inst.decoded_inst);
//				for (uint32_t i = 0; i < num_operands; ++i)
//				{
//					auto operand_name = xed_operand_name(xed_inst_operand(decoded_inst_inst, i));
//					if (XED_OPERAND_MEM0 == operand_name || XED_OPERAND_AGEN == operand_name)
//					{
//						auto base_reg = xed_decoded_inst_get_base_reg(&inst.decoded_inst, 0);
//						if (max_reg_width<XED_REG_RIP, Addr_width>::value == base_reg)
//						{
//							inst.used_link = rva + ilen + xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0);/* m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(
//								rva + ilen + xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)
//							);*/
//							inst.flags |= inst_flag::disp;
//						}
//						else if (XED_REG_INVALID == base_reg &&
//							xed_decoded_inst_get_memory_displacement_width_bits(&inst.decoded_inst, 0) == addr_width::bits<Addr_width>::value)
//						{
//							if (has_reloc)
//							{
//								inst.used_link = static_cast<uint64_t>(xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)) -
//									m_decoder_context->binary_interface->optional_header.get_image_base();
//								/*m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(
//									static_cast<uint64_t>(xed_decoded_inst_get_memory_displacement(&inst.decoded_inst, 0)) -
//									m_decoder_context->binary_interface->optional_header.get_image_base()
//								);*/
//								inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
//								inst.flags |= inst_flag::reloc_disp;
//							}
//						}
//					}
//					else if (has_reloc && XED_OPERAND_IMM0 == operand_name &&
//						xed_decoded_inst_get_immediate_width_bits(&inst.decoded_inst) == addr_width::bits<Addr_width>::value)
//					{
//						inst.used_link = xed_decoded_inst_get_unsigned_immediate(&inst.decoded_inst) -
//							m_decoder_context->binary_interface->optional_header.get_image_base();
//						/*m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(
//							xed_decoded_inst_get_unsigned_immediate(&inst.decoded_inst) -
//							m_decoder_context->binary_interface->optional_header.get_image_base()
//						);*/
//						inst.additional_data.reloc.original_rva = rva + inst.additional_data.reloc.offset_in_inst;
//						inst.flags |= inst_flag::reloc_imm;
//					}
//				}
//
//				rva += ilen;
//
//				// Update the end of the current block so its correct if we need to call split_block
//				cur_block_it->rva_end = rva;
//
//				// Follow control flow
//				//
//				auto cat = xed_decoded_inst_get_category(&inst.decoded_inst);
//				if (cat == XED_CATEGORY_COND_BR)
//				{
//					int32_t br_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
//					uint64_t taken_rva = rva + br_disp;
//
//					if (!m_decoder_context->validate_rva(taken_rva))
//					{
//						std::printf("Conditional branch to invalid rva.\n");
//						return current_routine->blocks.end();
//					}
//
//					inst.used_link = taken_rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(taken_rva);
//					inst.flags |= inst_flag::rel_br;
//
//					if (!m_lookup_table.is_inst_start(taken_rva))
//					{
//						if (decode_block(taken_rva) == current_routine->blocks.end())
//							return current_routine->blocks.end();
//
//						//if (m_decoder_context->routine_table[taken_rva] == true)
//						//{
//						//if (found_prologue)
//						m_decoder_context->relbr_table[taken_rva] = true;
//						//}
//					}
//					else
//					{
//						if (!split_block(taken_rva))
//							return current_routine->blocks.end();
//					}
//
//					auto fallthrough = decode_block(rva);
//					if (fallthrough == current_routine->blocks.end())
//						return current_routine->blocks.end();
//
//					cur_block_it->fallthrough_block = fallthrough;
//
//					goto ExitInstDecodeLoop;
//				}
//				else if (cat == XED_CATEGORY_UNCOND_BR)
//				{
//					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
//					{
//					case XED_IFORM_JMP_GPRv:
//						// Jump table.
//						//
//						std::printf("Unhandled inst[%08X]: XED_IFORM_JMP_GPRv.\n", rva - ilen);
//						return current_routine->blocks.end();
//					case XED_IFORM_JMP_MEMv:
//						if (!inst.used_link)
//						{
//							std::printf("Unhandled inst[%08X]: XED_IFORM_JMP_MEMv.\n", rva - ilen);
//							return current_routine->blocks.end();
//						}
//						goto ExitInstDecodeLoop;
//					case XED_IFORM_JMP_RELBRb:
//					case XED_IFORM_JMP_RELBRd:
//					case XED_IFORM_JMP_RELBRz:
//					{
//						int32_t jmp_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
//						uint64_t dest_rva = rva + jmp_disp;
//
//						if (!m_decoder_context->validate_rva(dest_rva))
//						{
//							std::printf("Unconditional branch to invalid rva.\n");
//							goto ExitInstDecodeLoop;
//						}
//						inst.used_link = dest_rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(dest_rva);
//						inst.flags |= inst_flag::rel_br;
//
//
//						// REWRITE ME
//						if (!m_lookup_table.is_inst_start(dest_rva))
//						{
//							// Here i will try to detect odd function calls that use a jump instead. 
//							//
//							if constexpr (Addr_width == addr_width::x64)
//							{
//								if (dest_rva < e_range_start || dest_rva >= e_range_end)
//								{
//									// No func data, this is a tail call to a leaf.
//									//
//									if (!m_decoder_context->binary_interface->data_table->has_func_data(dest_rva))
//									{
//										m_decoder_context->report_routine_rva(dest_rva);
//										goto ExitInstDecodeLoop;
//									}
//									else
//									{
//										// Not a leaf? lets see if the unwind info is the same
//										// If it is, this is just an oddly formed function
//										//
//										auto runtime_func = m_decoder_context->binary_interface->get_it<pex::image_runtime_function_it_t>(
//											m_decoder_context->binary_interface->data_table->get_func_data(rva).runtime_function_rva
//											);
//
//										// This relies on the fact that multiple runtime function structures for a single func will
//										// use the same unwind info structure, and the rvas will be the same
//										//
//										if (runtime_func.get_unwindw_info_address() != e_unwind_info)
//										{
//											m_decoder_context->report_routine_rva(dest_rva);
//											goto ExitInstDecodeLoop;
//										}
//									}
//								}
//							}
//
//							if (decode_block(dest_rva) == current_routine->blocks.end())
//								return current_routine->blocks.end();
//
//							//if (m_decoder_context->routine_table[dest_rva].load() == true)
//							//{
//							//if (found_prologue)
//							m_decoder_context->relbr_table[dest_rva] = true;
//							//}
//						}
//						else
//						{
//							if (!split_block(dest_rva))
//								return current_routine->blocks.end();
//						}
//
//						goto ExitInstDecodeLoop;
//					}
//					case XED_IFORM_JMP_FAR_MEMp2:
//					case XED_IFORM_JMP_FAR_PTRp_IMMw:
//						std::printf("Unhandled inst[%08X]: JMP_FAR_MEM/PTR.\n", rva - ilen);
//						return current_routine->blocks.end();
//					}
//				}
//				else if (cat == XED_CATEGORY_CALL && m_decoder_context->settings.recurse_calls)
//				{
//					switch (xed_decoded_inst_get_iform_enum(&inst.decoded_inst))
//					{
//					case XED_IFORM_CALL_NEAR_GPRv:
//						// Call table?!
//						//
//						std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_GPRv.\n", rva - ilen);
//						return current_routine->blocks.end();
//					case XED_IFORM_CALL_NEAR_MEMv:
//						// Import or call to absolute address...
//						//
//						if (!inst.used_link)
//						{
//							std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_NEAR_MEMv.\n", rva - ilen);
//							return current_routine->blocks.end();
//						}
//						break;
//
//					case XED_IFORM_CALL_NEAR_RELBRd:
//					case XED_IFORM_CALL_NEAR_RELBRz:
//					{
//						int32_t call_disp = xed_decoded_inst_get_branch_displacement(&inst.decoded_inst);
//						uint64_t dest_rva = rva + call_disp;
//						if (!m_decoder_context->validate_rva(dest_rva))
//						{
//							std::printf("Call to invalid rva.\n");
//							return current_routine->blocks.end();
//						}
//
//						//std::printf("Found call at 0x%X, 0x%X\n", rva - ilen, dest_rva);
//
//						inst.used_link = dest_rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(dest_rva);
//						inst.flags |= inst_flag::rel_br;
//
//						if (!m_lookup_table.is_self(dest_rva))
//						{
//							m_decoder_context->report_routine_rva(dest_rva);
//						}
//						break;
//					}
//					case XED_IFORM_CALL_FAR_MEMp2:
//					case XED_IFORM_CALL_FAR_PTRp_IMMw:
//						std::printf("Unhandled inst[%08X]: XED_IFORM_CALL_FAR_MEM/PTR.\n", rva - ilen);
//						return current_routine->blocks.end();
//					}
//				}
//				else if (cat == XED_CATEGORY_RET)
//				{
//					break;
//				}
//				else if (XED_ICLASS_INT3 == xed_decoded_inst_get_iclass(&inst.decoded_inst)/* && current_block.instructions.size() > 1*/)
//				{
//					break;
//				}
//			}
//
//			// If we make it here, we found an already decoded instruction and need to set the fallthrough
//			//
//			for (auto block_it_t = current_routine->blocks.begin(); block_it_t != current_routine->blocks.end(); ++block_it_t)
//			{
//				if (rva >= block_it_t->rva_start && rva < block_it_t->rva_end)
//				{
//					for (auto inst_it = block_it_t->instructions.begin(); inst_it != block_it_t->instructions.end(); ++inst_it)
//					{
//						if (inst_it->original_rva == rva)
//						{
//							cur_block_it->fallthrough_block = block_it_t;
//						}
//					}
//				}
//			}
//
//		ExitInstDecodeLoop:
//			cur_block_it->rva_end = rva;
//
//			return cur_block_it;
//		}
//		void decode(uint64_t rva)
//		{
//			if (!m_decoder_context->validate_rva(rva))
//			{
//				std::printf("Attempting to decode routine at invalid rva.\n");
//				return;
//			}
//			/*if (m_decoder_context->relbr_table[rva])
//			{
//				std::printf("Skipping decode on a proposed routine start that is actually just a function chunk. %X\n", rva);
//				return;
//			}*/
//
//			// Since this is only available for x64...
//			//
//			if constexpr (Addr_width == addr_width::x64)
//			{
//				if (m_decoder_context->binary_interface->data_table->unsafe_get_symbol_for_rva(rva).has_func_data())
//				{
//					e_runtime_func.set(m_decoder_context->binary_interface->mapped_image +
//						m_decoder_context->binary_interface->data_table->get_func_data(rva).runtime_function_rva);
//
//					e_range_start = e_runtime_func.get_begin_address();
//					e_range_end = e_runtime_func.get_end_address();
//					e_unwind_info = e_runtime_func.get_unwindw_info_address();
//				}
//			}
//
//			completed_routines.emplace_back();
//			current_routine = &completed_routines.back();
//
//			if (decode_block(rva) == current_routine->blocks.end())
//			{
//				++invalid_routine_count;
//				return;
//			}
//
//			current_routine->original_entry_rva = rva;
//			current_routine->entry_link = rva; // m_decoder_context->binary_interface->data_table->unsafe_get_symbol_index_for_rva(rva);
//		}
//	};
//
//
//	// Step1: FIND all code and put them into dasm_blocks which are just lists of consecutively executed
//	// instructions. these are not basic blocks because they only end at ABSOLUTE jumps or ret.
//	//
//	// Step2: Use a list of determined function entry points to use up blocks and create functions.
//	//
//	template<addr_width::type Addr_width = addr_width::x64>
//	class dasm2_t
//	{
//		pex::binary_t<Addr_width> m_binary;
//	};
//
//
//
//}