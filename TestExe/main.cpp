

#include <stdio.h>


#include "sdk.h"

struct hardware_info
{
	int core_count;
};

struct shellcode_struct
{
	using fn_get_module_handle = void*(*)(const char*);
	fn_get_module_handle get_module_handle;
	using fn_get_proc_address = void*(*)(void*, char*);
	fn_get_proc_address get_proc_address;

	// returns the packet ptr, 
	//Args: packed_id, packet_data, packet_data_size, returned_packet_size
	//This where we assemble protobuf structures.
	//Builds report packets that have
	//uint32_t id;
	//repeated uint8_t report_data;
	using fn_build_packet = void*(*)(unsigned int, void*, unsigned int, unsigned int* len);
	fn_build_packet build_packet;

	using fn_send_packet = void(*)(void*, unsigned int);
	fn_send_packet send_packet;

	char* meme;

};

__declspec(noinline) void* shellcode_test(shellcode_struct* scst)
{
	/*union { char data[87]; struct { unsigned char ch0; unsigned char ch1; unsigned char ch2; unsigned char ch3; unsigned char ch4; unsigned char ch5; unsigned char ch6; unsigned char ch7; unsigned char ch8; unsigned char ch9; unsigned char ch10; unsigned char ch11; unsigned char ch12; unsigned char ch13; unsigned char ch14; unsigned char ch15; unsigned char ch16; unsigned char ch17; unsigned char ch18; unsigned char ch19; unsigned char ch20; unsigned char ch21; unsigned char ch22; unsigned char ch23; unsigned char ch24; unsigned char ch25; unsigned char ch26; unsigned char ch27; unsigned char ch28; unsigned char ch29; unsigned char ch30; unsigned char ch31; unsigned char ch32; unsigned char ch33; unsigned char ch34; unsigned char ch35; unsigned char ch36; unsigned char ch37; unsigned char ch38; unsigned char ch39; unsigned char ch40; unsigned char ch41; unsigned char ch42; unsigned char ch43; unsigned char ch44; unsigned char ch45; unsigned char ch46; unsigned char ch47; unsigned char ch48; unsigned char ch49; unsigned char ch50; unsigned char ch51; unsigned char ch52; unsigned char ch53; unsigned char ch54; unsigned char ch55; unsigned char ch56; unsigned char ch57; unsigned char ch58; unsigned char ch59; unsigned char ch60; unsigned char ch61; unsigned char ch62; unsigned char ch63; unsigned char ch64; unsigned char ch65; unsigned char ch66; unsigned char ch67; unsigned char ch68; unsigned char ch69; unsigned char ch70; unsigned char ch71; unsigned char ch72; unsigned char ch73; unsigned char ch74; unsigned char ch75; unsigned char ch76; unsigned char ch77; unsigned char ch78; unsigned char ch79; unsigned char ch80; unsigned char ch81; unsigned char ch82; unsigned char ch83; unsigned char ch84; unsigned char ch85; unsigned char ch86; }; }test;
	{test.ch0 = 0x5; test.ch1 = 0x4f; test.ch2 = 0x0; test.ch3 = 0x18; test.ch4 = 0x43; test.ch5 = 0x10; test.ch6 = 0xd; test.ch7 = 0x10; test.ch8 = 0x7; test.ch9 = 0x59; test.ch10 = 0x2; test.ch11 = 0x45; test.ch12 = 0x5; test.ch13 = 0x12; test.ch14 = 0x0; test.ch15 = 0x4; test.ch16 = 0x45; test.ch17 = 0x42; test.ch18 = 0x1e; test.ch19 = 0x9; test.ch20 = 0x26; test.ch21 = 0x4b; test.ch22 = 0x1d; test.ch23 = 0x0; test.ch24 = 0x6; test.ch25 = 0x4; test.ch26 = 0x45; test.ch27 = 0xb; test.ch28 = 0x55; test.ch29 = 0xd; test.ch30 = 0x1; test.ch31 = 0x54; test.ch32 = 0x18; test.ch33 = 0x48; test.ch34 = 0x43; test.ch35 = 0x61; test.ch36 = 0x0; test.ch37 = 0x48; test.ch38 = 0x1c; test.ch39 = 0x73; test.ch40 = 0x11; test.ch41 = 0x7; test.ch42 = 0x15; test.ch43 = 0x79; test.ch44 = 0x1c; test.ch45 = 0x79; test.ch46 = 0xc; test.ch47 = 0x39; test.ch48 = 0x60; test.ch49 = 0x25; test.ch50 = 0x13; test.ch51 = 0x11; test.ch52 = 0x8; test.ch53 = 0x22; test.ch54 = 0x71; test.ch55 = 0x21; test.ch56 = 0x20; test.ch57 = 0x4d; test.ch58 = 0x65; test.ch59 = 0x6a; test.ch60 = 0x33; test.ch61 = 0x27; test.ch62 = 0x14; test.ch63 = 0x75; test.ch64 = 0x68; test.ch65 = 0x53; test.ch66 = 0x34; test.ch67 = 0x36; test.ch68 = 0x6; test.ch69 = 0x11; test.ch70 = 0x5a; test.ch71 = 0xb; test.ch72 = 0x29; test.ch73 = 0x61; test.ch74 = 0x43; test.ch75 = 0x43; test.ch76 = 0x7b; test.ch77 = 0x6d; test.ch78 = 0x2d; test.ch79 = 0x68; test.ch80 = 0x2c; test.ch81 = 0x25; test.ch82 = 0x47; test.ch83 = 0x62; test.ch84 = 0x6f; test.ch85 = 0x61; test.ch85 ^= test.ch1; test.ch84 ^= test.ch38; test.ch83 ^= test.ch7; test.ch82 ^= test.ch53; test.ch81 ^= test.ch17; test.ch80 ^= test.ch21; test.ch79 ^= test.ch30; test.ch78 ^= test.ch75; test.ch77 ^= test.ch57; test.ch76 ^= test.ch7; test.ch75 ^= test.ch56; test.ch74 ^= test.ch67; test.ch73 ^= test.ch41; test.ch72 ^= test.ch19; test.ch71 ^= test.ch75; test.ch70 ^= test.ch85; test.ch69 ^= test.ch75; test.ch68 ^= test.ch81; test.ch67 ^= test.ch65; test.ch66 ^= test.ch62; test.ch65 ^= test.ch72; test.ch64 ^= test.ch30; test.ch63 ^= test.ch22; test.ch62 ^= test.ch48; test.ch61 ^= test.ch8; test.ch60 ^= test.ch28; test.ch59 ^= test.ch0; test.ch58 ^= test.ch16; test.ch57 ^= test.ch58; test.ch56 ^= test.ch28; test.ch55 ^= test.ch17; test.ch54 ^= test.ch10; test.ch53 ^= test.ch10; test.ch52 ^= test.ch57; test.ch51 ^= test.ch45; test.ch50 ^= test.ch80; test.ch49 ^= test.ch12; test.ch48 ^= test.ch0; test.ch47 ^= test.ch21; test.ch46 ^= test.ch57; test.ch45 ^= test.ch9; test.ch44 ^= test.ch48; test.ch43 ^= test.ch42; test.ch42 ^= test.ch68; test.ch41 ^= test.ch50; test.ch40 ^= test.ch70; test.ch39 ^= test.ch22; test.ch38 ^= test.ch65; test.ch37 ^= test.ch77; test.ch36 ^= test.ch49; test.ch35 ^= test.ch3; test.ch34 ^= test.ch20; test.ch33 ^= test.ch53; test.ch32 ^= test.ch43; test.ch31 ^= test.ch50; test.ch30 ^= test.ch79; test.ch29 ^= test.ch78; test.ch28 ^= test.ch53; test.ch27 ^= test.ch60; test.ch26 ^= test.ch34; test.ch25 ^= test.ch76; test.ch24 ^= test.ch74; test.ch23 ^= test.ch61; test.ch22 ^= test.ch78; test.ch21 ^= test.ch58; test.ch20 ^= test.ch11; test.ch19 ^= test.ch33; test.ch18 ^= test.ch83; test.ch17 ^= test.ch36; test.ch16 ^= test.ch48; test.ch15 ^= test.ch68; test.ch14 ^= test.ch32; test.ch13 ^= test.ch84; test.ch12 ^= test.ch57; test.ch11 ^= test.ch15; test.ch10 ^= test.ch21; test.ch9 ^= test.ch44; test.ch8 ^= test.ch22; test.ch7 ^= test.ch35; test.ch6 ^= test.ch40; test.ch5 ^= test.ch55; test.ch4 ^= test.ch20; test.ch3 ^= test.ch46; test.ch2 ^= test.ch43; test.ch1 ^= test.ch36; test.ch0 ^= test.ch57; test.ch86 = '\0'; }
	printf("the string %s\n", test.data);*/

	if (scst->build_packet)
		return scst->get_module_handle(scst->meme);
	return NULL;
}


//holy christ im such a beast.
__declspec(noinline) int other_routine()
{
	BDASM_Begin(MARKER_ATTRIBUTE_ENTIRE_FUNCTION, 0);

	printf("this is the other routine.\n");

	return 12;
}


int main()
{
	//BDASM_Begin(MARKER_ATTRIBUTE_ENTIRE_FUNCTION, 0);

	printf("Hello Test. %llu\n", 0xFFEACC0DEF);
	int meme = other_routine();

	void* meme2 = shellcode_test(new shellcode_struct);

	BDASM_End();
	return meme;
}