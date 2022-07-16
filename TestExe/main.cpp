

#include <stdio.h>


#include "sdk.h"
#include <stdlib.h>
#include <Windows.h>


//holy christ im such a beast.
__declspec(noinline) int other_routine()
{
	//BDASM_Begin(MARKER_ATTRIBUTE_EXTEND_TO_FUNC_START, 0);
	printf("this is the other routine.\n");
	//BDASM_End();

	//BDASM_Begin(MARKER_ATTRIBUTE_EXTEND_TO_FUNC_END, 0);
	printf("this is the other routine.2\n");
	//BDASM_End();

	return 12;
}


int main(int argc, char** argv)
{
	/*if (argc == 1)
	{
		printf("it was 1.\n");
	}
	printf("it was 1.\n");
	system("pause");
	return 1;*/

	int memes = rand() % 3;
	if (argc == 1)
	{
		memes = 1776 + 34;
		printf("it was 1. %X %X\n", argc + 2, memes);
	}
	else
	{
		memes = 19912 + 12;
		printf("it wasnt 1. %X %X\n", argc + 3, memes);
	}

	argc = rand() % 2;
	printf("hello there. %X %X\n", argc, memes);

	other_routine();

	system("pause");
	return 12;




	////BDASM_Begin(MARKER_ATTRIBUTE_ENTIRE_FUNCTION, 0);

	//printf("Hello Test. %llu\n", 0xFFEACC0DEF);
	//int meme = other_routine();

	//printf("Result was %d\n", meme);
	//system("pause");

	/*__try
	{
		for (int i = 0; i < 10; i++)
		{
			printf("Heres an int %d\n", i);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		printf("here lies our exception handler.\n");
	}*/

	return 1;
}