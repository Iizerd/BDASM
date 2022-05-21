
#include <stdio.h>
#include <Windows.h>
#include <fstream>

#include "inst.h"
#include "sff.h"
#include "symbol.h"
#include "disasm.h"
#include "pex.h"
//uint8_t bytes[] = { 0xFF, 0x15, 0x00 ,0x30 ,0x40 ,0x00 };
//uint8_t bytes[] = { 0x48,0xFF ,0x15 ,0x39 ,0x6C ,0xC3 ,0xFF };

//#define image_name "C:\\$Fanta\\FntaDrvr\\x64\\Release\\ShellcodeMaker.exe"

#define image_name "C:\\$Fanta\\CV2\\x64\\Release\\CV2.exe"

int main(int argc, char** argv)
{

	xed_tables_init();
	

	std::string binary_path = image_name;

	if (argc == 2)
		binary_path = argv[1];

	address_width width = binary_ir_t<>::deduce_address_width(binary_path);
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



	if (width == address_width::x86)
	{
		binary_ir_t<address_width::x86> binary;
		if (!binary.from_memory(FileBuffer, FileLength))
			printf("failed.\n");
	}
	else if (width == address_width::x64)
	{
		binary_ir_t<address_width::x64> binary;
		if (!binary.from_memory(FileBuffer, FileLength))
			printf("failed.\n");

		printf("Entry point %X\n", binary.get_offset_of_entry_point());

		x86_dasm_t<address_width::x64> dasm(FileBuffer, FileLength, &binary.m_symbol_table, binary.m_optional_header.get_image_base());
		dasm.set_malformed_functions(true);
		dasm.set_recurse_calls(true);
		dasm.set_max_thread_count(8);
		/*dasm.set_block_progress_callback([](inst_block_t<address_width::x64> const& block)
			{
				std::printf("Created block with %llu insts at [%016X:%016X]\n", block.instructions.size(), block.start, block.end);
			});*/

		std::atomic_uint32_t routine_count = 0;
		std::atomic_uint32_t inst_count = 0;
		dasm.set_routine_progress_callback([&routine_count, &inst_count](uint32_t instruction_count)
			{
				routine_count++;
				inst_count += instruction_count;
				std::printf("Created routine with %u instructions.\n", instruction_count);
			});


		//dasm.do_routine(binary.get_offset_of_entry_point());

		std::vector<uint64_t> routine_pointers;

		routine_pointers.push_back(binary.get_offset_of_entry_point());
		for (auto i : binary.m_exports.entries)
		{
			routine_pointers.push_back(i.pointer_to_raw_data);
		}

		dasm.set_routine_pointers(routine_pointers);

		std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();

		dasm.go();

		std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();

		printf("disasembled a total of %u %u finished_routines and %u instructions.\n In %u ms\n", 
			routine_count.load(), 
			dasm.finished_routines.size(),
			inst_count.load(),
			std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
		);

		//printf("Symbo Count: %u\n", binary.m_symbol_table.)

		//dasm.routines.back().print_blocks();
		system("pause");
	}
	else
		printf("invalid addr width.");














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

	//symbol_table_t sym_table;
	//x86_dasm_t<address_width::x64> dasm((uint8_t*)FileBuffer, FileLength, &sym_table);
	//dasm.set_malformed_functions(false);
	//dasm.set_recurse_calls(true);
	//dasm.set_block_progress_callback([](inst_block_t<address_width::x64> const& block)
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

