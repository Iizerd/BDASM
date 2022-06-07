
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
#include "disasm.h"
#include "dasm.h"
#include "pex.h"
#include "marker.h"
#include "obf.h"
#include "off.h"

#include "dpattern.h"
//uint8_t bytes[] = { 0xFF, 0x15, 0x00 ,0x30 ,0x40 ,0x00 };
//uint8_t bytes[] = { 0x48,0xFF ,0x15 ,0x39 ,0x6C ,0xC3 ,0xFF };

//#define image_name "C:\\$Fanta\\FntaDrvr\\x64\\Release\\ShellcodeMaker.exe"
#define image_name "C:\\Users\\Iizerd\\Desktop\\revers windas\\ntoskrnl.exe"
//#define image_name "C:\\$Fanta\\CV2\\x64\\Release\\CV2.exe"

//#ifdef _DEBUG
//#define image_name "C:\\$Work\\BDASM\\x64\\Debug\\TestExe.exe"
//#else
//#define image_name "C:\\$Work\\BDASM\\x64\\Release\\TestExe.exe"
//#endif

//#define image_name "C:\\$Fanta\\sballizerdware\\x64\\Release\\FantaShellcode.exe"

int main(int argc, char** argv)
{
	/*static constexpr dasm::static_ipattern_t<dasm::address_width::x64, XED_ICLASS_CALL_FAR, XED_ICLASS_JB> pattern;

	std::printf("Pattern Size: %u\n", pattern.size);

	for (uint32_t i = 0; i < pattern.size; i++)
		std::printf("Pattern Class: %s\n", xed_iclass_enum_t2str(pattern.pattern[i]));

	system("pause");
	return 1;*/


	xed_tables_init();

	std::string binary_path = image_name;

	if (argc == 2)
		binary_path = argv[1];

	dasm::address_width width = binary_ir_t<>::deduce_address_width(binary_path);
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



	if (width == dasm::address_width::x86)
	{
		binary_ir_t<dasm::address_width::x86> binary;
		if (!binary.map_image(FileBuffer, FileLength))
			printf("failed.\n");
	}
	else if (width == dasm::address_width::x64)
	{
		binary_ir_t<dasm::address_width::x64> binary;
		if (!binary.map_image(FileBuffer, FileLength))
			printf("failed.\n");

		printf("Entry point %X\n", binary.optional_header.get_address_of_entry_point());

		obf::binary_obfuscator_t<dasm::address_width::x64, 6> obfuscator;
		
		std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
		obfuscator.load_file(binary_path);
		std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();

		//dasm.print_details();
		std::printf("it took %ums\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

		std::printf("Routines Count: %u\n", obfuscator.m_dasm->completed_routines.size());

		/*obfuscator.enumerate_marked_functions();

		obfuscator.export_marked_routine_and_nop_marker("C:\\$Work\\BDASM\\x64\\Release\\");*/




		//std::mutex memelock;
		//decoder_context_t decode_context(binary.mapped_image, binary.optional_header.get_size_of_image(), &binary.symbol_table, &memelock);
		//decode_context.settings.recurse_calls = true;

		//dasm_t<address_width::x64, 1> dasm(&decode_context);
		//dasm.is_executable = std::bind(&binary_ir_t<address_width::x64>::is_rva_in_executable_section, &binary, std::placeholders::_1);

		//dasm.add_routine(binary.optional_header.get_address_of_entry_point());

	
		///*for (image_runtime_function_it_t m_runtime_functions(reinterpret_cast<image_runtime_function_entry_t*>(binary.mapped_image + binary.optional_header.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).get_virtual_address()));
		//	!m_runtime_functions.is_null(); ++m_runtime_functions)
		//{
		//	if (binary.is_rva_in_executable_section(m_runtime_functions.get_begin_address()))
		//		dasm.add_routine(m_runtime_functions.get_begin_address());
		//}*/

		//
		///*for (auto& i : binary.m_exports.entries)
		//{
		//	if (binary.is_rva_in_executable_section(i.rva))
		//		dasm.add_routine(i.rva);
		//}*/
		//
		//std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();

		//dasm.run();

		//dasm.wait_for_completion();

		//std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();

		//dasm.print_details();
		//std::printf("it took %ums\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());


		//for (auto& routine : dasm.completed_routines)
		//{
		//	if (routine.blocks.size() > 1)
		//	{
		//		routine.block_trace();
		//		//system("pause");
		//	}
		//	for (auto& block : routine.blocks)
		//	{
		//		if (find_begin_marker(block.instructions) != block.instructions.end())
		//		{
		//			std::printf("Found a begin marker. %llu blocks.\n", routine.blocks.size());
		//		}
		//		if (find_end_marker(block.instructions) != block.instructions.end())
		//		{
		//			std::printf("Found an end marker. %llu blocks.\n", routine.blocks.size());
		//		}
		//		std::printf("Checked routine with %llu blocks.\n", routine.blocks.size());
		//		
		//	}
		//}
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

