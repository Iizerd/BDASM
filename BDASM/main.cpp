
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
#define image_name "C:\\@\\Work\\BDASM\\x64\\Release\\TestExe.exe"
#define image_out "C:\\@\\Work\\BDASM\\x64\\Release\\TestExe2.exe"
//#endif

//#define image_name "C:\\$Fanta\\sballizerdware\\x64\\Release\\FantaShellcode.exe"

int main(int argc, char** argv)
{
	xed_tables_init();

	std::string binary_path = image_name;

	if (argc == 2)
		binary_path = argv[1];

	dasm::addr_width::type width = pex::binary_t<>::deduce_address_width(binary_path);
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



	if (width == dasm::addr_width::x86)
	{
		pex::binary_t<dasm::addr_width::x86> binary;
		if (!binary.map_image(FileBuffer, FileLength))
			printf("failed.\n");
	}
	else if (width == dasm::addr_width::x64)
	{
		pex::binary_t<dasm::addr_width::x64> binary;
		if (!binary.map_image(FileBuffer, FileLength))
			printf("failed.\n");

		printf("Entry point %X\n", binary.optional_header.get_address_of_entry_point());

		dasm::decoder_context_t<dasm::addr_width::x64> context(&binary);
		context.settings.recurse_calls = true;

		dasm::dasm_t<dasm::addr_width::x64> disassembler(&context);

		disassembler.add_routine(binary.optional_header.get_address_of_entry_point());
		
		disassembler.run();
		disassembler.wait_for_completion();

		printf("Found %d routines.\n", disassembler.completed_routines.size());
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

