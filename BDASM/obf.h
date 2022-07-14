

#include "obf_structures.h"
#include "align.h"

// Passes
//
#include "mba.h"
#include "pi_blocks.h"
#include "stack_allocation.h"
#include "opaques.h"
#include "original.h"

namespace obf
{
	//https://www.youtube.com/watch?v=pXwbj_ZPKwg&ab_channel=VvporTV
	//
	template<addr_width::type Addr_width = addr_width::x64, uint32_t Thread_count = 1>
	class obf_t
	{

		dasm::decoder_context_t<Addr_width>* m_decoder_context;

		dasm::linker_t* m_linker;
	public:

		dasm::dasm_t<Addr_width, Thread_count>* dasm;

		pex::binary_t<Addr_width>* bin;

		std::list<routine_t<Addr_width> > obf_routines;

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
				if (routine.entry_block->calc_byte_sizes() > 5/*&& routine.entry_block->rva_start == 0x13A8*//*0x13A8*/)
				{
					routine.promote_relbrs();
					obf_routines.emplace_back(routine);
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


		void run()
		{
			context_t<Addr_width> context = { m_linker, bin, obf_routines };

			for (auto& routine : obf_routines)
			{
				//	//routine.m_routine.blocks.sort([](dasm::block_t<Addr_width>& left, dasm::block_t<Addr_width>& right)
				//	//	{
				//	//		return left.rva_start < right.rva_start;
				//	//	});
				//	//printf("\n\nROUTINE AT %X %u\n", routine.m_routine.entry_block->rva_start, routine.m_routine.blocks.size());

				//if (routine.m_routine.entry_block->rva_start == 0x1530)
				//	routine.m_routine.print_blocks();
				//	//int32_t alloc_size = 0x400;
				//	//auto pass_status = routine.mutation_pass<stack_allocation_t>(context, alloc_size);
				//	//std::printf("allocated with %X %d\n", alloc_size, pass_status);
				//	routine.mutation_pass< opaque_from_flags_t>(context);


				// Make sure this is run first before any passes that invalidate rva_start and rva_end are run
				//
				routine.mutation_pass<pad_original_t>(context);


				routine.mutation_pass<opaque_from_flags_t>(context);

				routine.mutation_pass<position_independent_blocks_t>(context);
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
				}/*
				for (auto& block : routine.m_routine.blocks)
				{
					block.place_in_binary(rva, m_linker);
				}*/


				rva = align_up(rva, 0x10);
			}
			return rva;
		}
		void encode(uint32_t section_size)
		{
			uint64_t rva = bin->append_section(".TEST", section_size, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE, true);
			auto dest = bin->mapped_image + rva;
			for (auto& routine : obf_routines)
			{
				/*if (routine.m_routine.entry_block->rva_start == 0x13A8)
				{
					printf("\n\n");
					routine.m_routine.print_blocks(m_linker);
					printf("placing routine at 0x%X\n", dest - bin->mapped_image);
				}*/
				for (auto& block : routine.m_routine.blocks)
				{
					block.encode_in_binary(bin, m_linker, &dest);

				}

				dest = align_up_ptr(dest, 0x10);

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