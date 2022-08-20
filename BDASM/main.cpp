
/*
*	Problems:
*		- Seems as though the execption handlers are not found. Probably because
*		  there is no direct jump into them. Maybe can ignore this for now...
*/
#include <stdio.h>
#include <Windows.h>
#include <fstream>

#include "inst.h"
#include "sff.h"
#include "symbol.h"
#include "dasm.h"
#include "pex.h"

#include "dpattern.h"

#include "obf.h"

// Passes
//
#include "mba.h"
#include "pi_blocks.h"
#include "stack_allocation.h"
#include "opaques.h"
#include "original.h"
#include "encrypted_blocks.h"
#include "encrypted_routines.h"
#include "flat_control.h"
#include "constant_encryption.h"



//uint8_t bytes[] = { 0xFF, 0x15, 0x00 ,0x30 ,0x40 ,0x00 };
//uint8_t bytes[] = { 0x48,0xFF ,0x15 ,0x39 ,0x6C ,0xC3 ,0xFF };

//#define image_name "C:\\$Fanta\\FntaDrvr\\x64\\Release\\ShellcodeMaker.exe"
//#define image_name "C:\\Users\\Iizerd\\Desktop\\revers windas\\ntoskrnl.exe"
//#define image_name "C:\\Users\\Iizerd\\Desktop\\revers windas\\dxgkrnl.sys"
//#define image_name "C:\\$Fanta\\CV2\\x64\\Release\\CV2.exe"

//#ifdef _DEBUG
//#define image_name "C:\\$Work\\BDASM\\x64\\Debug\\TestExe.exe"
//#define image_out "C:\\$Work\\BDASM\\x64\\Debug\\TestExe2.exe"
//#else
//#define image_name "C:\\@\\Work\\BDASM\\x64\\Release\\TestExe.exe"

//#define image_name "C:\\$Work\\BDASM\\x64\\Release\\TestExe.exe"

#define image_name "C:\\$Work\\CrackmeTest\\x64\\Release\\CrackmeTest.exe"

//#define image_name "C:\\Users\\James\\Desktop\\Reverse Windas\\dxgkrnl.sys"
#define image_out "C:\\$Work\\BDASM\\x64\\Release\\TestExe4.exe"
//#endif

//#define image_name "C:\\$Fanta\\sballizerdware\\x64\\Release\\FantaShellcode.exe"


int main(int argc, char** argv)
{
	srand(time(nullptr));
	xed_tables_init();

	auto rand_val = ((0x24121 << 4) | (1 << 0));

	auto addr = 0xC00023;
	auto temp = addr;
	do
	{
		addr += rand_val;
	} while (addr & 0xF);

	do
	{
		addr -= (rand_val - 1);
	} while (temp < addr);

	addr += (rand_val - 1);

	printf("Results are %X %X\n", addr, rand_val, temp);

	//uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];

	//dasm::inst_t<addr_width::x64> inst(
	//	XED_ICLASS_NOP,
	//	32
	//);

	///*dasm::inst_t<addr_width::x64> inst;

	//

	//auto len = encode_inst_in_place(buffer, addr_width::machine_state<addr_width::x64>::value, 
	//	XED_ICLASS_XCHG,
	//	8,
	//	xed_mem_bd(
	//		max_reg_width<XED_REG_RIP, addr_width::x64>::value,
	//		xed_disp(0, 32),
	//		8
	//	),
	//	xed_reg(XED_REG_AL)
	//);*/


	//inst.dumb_encode(buffer);

	//for (auto i = 0; i < inst.length(); i++)
	//{
	//	std::printf("%02X ", buffer[i]);
	//}
	//std::printf("\n");

	//return 1;
	obf::obf_t<addr_width::x64> obfuscator;

	obfuscator.load_file(image_name);

	obfuscator.register_single_pass<pad_original_t>();
	//obfuscator.register_single_pass<opaque_from_rip_t>();
	//obfuscator.register_single_pass<opaque_from_flags_t>();
	obfuscator.register_single_pass<flatten_control_flow_t>();
	obfuscator.register_single_pass<constant_encryption_t>();
	//obfuscator.register_single_pass<stack_allocation_t>(0x100);
	//obfuscator.register_single_pass<opaque_from_const_t>();
	//obfuscator.register_single_pass<position_independent_blocks_t>();
	//obfuscator.register_single_pass<encrypted_routine_t>();

	obfuscator.run_single_passes();

	printf("staritng placement.\n");
	obfuscator.encode(obfuscator.place());

	obfuscator.save_file(image_out);
	system("pause");
	return 1;



	//uint8_t memes[] = { 0x48, 0x81, 0xEC, 0xB8, 0x22, 0x00, 0x00 };

	//dasm::inst64_t inst;
	//inst.decode(memes, sizeof(memes));
	//std::printf("iform is %s\n", xed_iform_enum_t2str(xed_decoded_inst_get_iform_enum(&inst.decoded_inst)));
	//std::printf("signed = %d\n", xed_decoded_inst_get_immediate_is_signed(&inst.decoded_inst));

	//return 1;
	std::string binary_path = image_name;

	if (argc == 2)
		binary_path = argv[1];

	addr_width::type width = pex::binary_t<>::deduce_address_width(binary_path);
	//printf("image size %u %u\n", address_width_to_bits(width), address_width_to_bytes(width));

	std::ifstream SffFile(binary_path, std::ios::binary);
	SffFile.seekg(0, std::ios::end);
	size_t FileLength = SffFile.tellg();
	SffFile.seekg(0, std::ios::beg);
	uint8_t* FileBuffer = (uint8_t*)malloc(FileLength);
	if (!FileBuffer)
		return 1;
	SffFile.read((PCHAR)FileBuffer, FileLength);
	SffFile.close();



	if (width == addr_width::x86)
	{
		pex::binary_t<addr_width::x86> binary;
		if (!binary.map_image(FileBuffer, FileLength))
			printf("failed.\n");
	}
	else if (width == addr_width::x64)
	{
		pex::binary_t<addr_width::x64> binary;
		if (!binary.map_image(FileBuffer, FileLength))
			printf("failed.\n");

		printf("Entry point %X\n", binary.optional_header.get_address_of_entry_point());

		dasm::decoder_context_t<addr_width::x64> context(&binary);
		context.settings.recurse_calls = true;
		context.linker = new dasm::linker_t(binary.optional_header.get_size_of_image(), 0x10000);

		dasm::dasm_t<addr_width::x64, 8> disassembler(&context);

		disassembler.add_routine(binary.optional_header.get_address_of_entry_point());


		for (auto& exp : binary.m_exports.entries)
		{
			disassembler.add_routine(exp.rva);
		}

		uint32_t count = 0;
		auto addr = binary.mapped_image + binary.optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).get_virtual_address();
		for (pex::image_runtime_function_it_t m_runtime_functions(reinterpret_cast<pex::image_runtime_function_entry_t*>(addr));
			!m_runtime_functions.is_null(); ++m_runtime_functions)
		{
			if (binary.is_rva_in_executable_section(m_runtime_functions.get_begin_address()))
				disassembler.add_routine(m_runtime_functions.get_begin_address());
			count++;
		}
		printf("added %u runtime functions\n", count);
		auto start_time = std::chrono::high_resolution_clock::now();
		disassembler.run();
		disassembler.wait_for_completion();

		auto time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time);

		printf("Took %ums\n", time.count());

		printf("Found %llu routines.\n", disassembler.completed_routines.size());

		uint32_t block_count = 0;
		uint32_t block_max = 0;
		uint32_t rva_of_max;
		for (auto& rou : disassembler.completed_routines)
		{
			/*for (auto& block : rou.blocks)
			{
				if (block.termination_type == dasm::termination_type_t::invalid)
					std::printf("block terminatn invalid at %X %X\n", block.rva_start, block.rva_end);
			}*/
			block_count += rou.blocks.size();
			if (rou.blocks.size() > block_max)
			{
				block_max = rou.blocks.size();
				rva_of_max = rou.entry_link;
			}
		}

		std::printf("Found %u blocks. %u was the max in one func(%X)\n", block_count, block_max, rva_of_max);

		std::set<uint64_t> rvaset;

		/*for (auto& rou : disassembler.completed_routines)
		{
			rvaset.insert(rou.original_entry_rva);
		}

		std::ifstream filememe2("C:\\@\\Work\\BDASM\\x64\\Release\\test.txt");
		std::string temp = "";
		while (filememe2 >> temp)
		{
			rvaset.erase(std::stoull(temp, nullptr, 16));
		}*/


		//std::ifstream filememe2("C:\\@\\Work\\BDASM\\x64\\Release\\test.txt");
		//std::string temp = "";
		//while (filememe2 >> temp)
		//{
		//	rvaset.insert(std::stoull(temp, nullptr, 16));
		//}

		//std::vector<uint64_t> sorted_rvas;
		//for (auto& rou : disassembler.completed_routines)
		//{
		//	sorted_rvas.push_back(rou.entry_link);
		//	rvaset.erase(rou.entry_link);
		//}


		//std::sort(std::begin(sorted_rvas), end(sorted_rvas));
		//std::ofstream rvasfile("C:\\@\\Work\\BDASM\\x64\\Release\\rvas.txt");
		//for (auto const rva : sorted_rvas)
		//	rvasfile << "0x" << std::hex << rva << "\n";
		//rvasfile.close();


		/*for (auto rva : rvaset)
		{
			std::printf("Rva: %X\n", rva);
		}*/

		printf("total: %llu\n", rvaset.size());

		/*for (auto& rou : disassembler.completed_routines)
		{
			if (rou.entry_link == 0x1030)
			{
				rou.blocks.sort([](dasm::block_t<addr_width::x64> const& l, dasm::block_t<addr_width::x64> const& r)
					{
						return (l.rva_start < r.rva_start);
					});
				printf("Found main:\n");
				for (auto& blo : rou.blocks)
				{
					std::printf("Block: %X\n", blo.rva_start, blo.rva_end);
					for (auto& inst : blo.instructions)
						std::printf("\t%s\n", xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&inst.decoded_inst)));
					if (blo.fallthrough_block != rou.blocks.end())
						std::printf("Fallthrough %X\n", blo.fallthrough_block->rva_start);
				}
			}
		}*/

		auto& routine = disassembler.completed_routines.front();

		routine.blocks.sort([](dasm::block_t<addr_width::x64> const& l, dasm::block_t<addr_width::x64> const& r)
			{
				return (l.rva_start < r.rva_start);
			});
		printf("Found main:\n");
		//routine.print_blocks();
		uint32_t i = 0;

		//routine.blocks.front().clear();
		//std::next(routine.blocks.begin())->clear();
		//std::prev(routine.blocks.end())->clear();
		//for (auto it = routine.begin(); it != routine.end(); ++it)
		//{
		//	i++;
		//	printf("IClass %s\n", xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&it->decoded_inst)));
		//}
		system("pause");
		for (auto& block : routine.blocks)
			for (auto& inst : block.instructions)
				i++;
		// SHOULD SEE 98 instructions
		printf("%u instructions at %X\n", i, routine.entry_link);

	}
	else
		printf("invalid addr width.");


	system("pause");











	///*inst_t inst;
	//if (!inst.decode(bytes, sizeof(bytes)))
	//{
	//	printf("failed to decode");
	//	system("pause");
	//	return 0;
	//}

	//printf("iform: %s\n", xed_iform_enum_t2str(xed_decoded_inst_get_iform_enum(&inst.decoded_inst)));*/


	//std::ifstream SffFile("C:\\$Fanta\\FntaDrvr\\x64\\Release\\FntaDrvr.sc", std::ios::binary);

	//SffFile.seekg(0, std::ios::end);
	//size_t FileLength = SffFile.tellg();
	//SffFile.seekg(0, std::ios::beg);
	//PDECOMP_FILE FileBuffer = (PDECOMP_FILE)malloc(FileLength);
	//if (!FileBuffer)
	//	return 1;
	//SffFile.read((PCHAR)FileBuffer, FileLength);
	//SffFile.close();

	//SffVerify(FileBuffer);
	//SffDbgPrint(FileBuffer);

	//uint8_t* bytes = (uint8_t*)FileBuffer + FileBuffer->Functions[0].Offset;


	////uint8_t bytes[] = { 0x31, 0xC0, 0x31, 0xC0, 0x75, 0x04, 0x09, 0xC0, 0x09, 0xC0, 0x21, 0xC0, 0x21, 0xC0 };

	//bin_data_table_t sym_table;
	//x86_dasm_t<address_width::x64> dasm((uint8_t*)FileBuffer, FileLength, &sym_table);
	//dasm.set_malformed_functions(false);
	//dasm.set_recurse_calls(true);
	//dasm.set_block_progress_callback([](dasm_decode_block_t<address_width::x64> const& block)
	//	{
	//		std::printf("Created block with %llu insts at [%016X:%016X]\n", block.instructions.size(), block.start, block.end);
	//	});

	//dasm.set_routine_progress_callback([](uint32_t block_count)
	//	{
	//		std::printf("Created routine with %u blocks.\n", block_count);
	//	});



	//dasm.do_routine(FileBuffer->Functions[0].Offset);
	//dasm.routines.back().print_blocks();
}








//// for writeup
//
//
//template<addr_width::type aw>
//uint32_t get_len_of_mov_reg_imm()
//{
//	uint8_t buffer[XED_MAX_INSTRUCTION_BYTES];
//	return encode_inst_in_place(
//		buffer,
//		addr_width::machine_state<aw>::value,	// Machine state template
//		XED_ICLASS_MOV,							// Instruction Class
//		addr_width::bits<aw>::value,			// Effective operand width template
//		max_reg_width<XED_REG_RAX, aw>::value,	// Equates to max size of a given register based on address width
//		xed_imm0(								// Creates an immediate value of size 32 or 64 based on ''
//			0xABBA,
//			addr_width::bits<aw>::value,
//			)
//	);
//}