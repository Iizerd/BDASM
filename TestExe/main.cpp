

#include <stdio.h>


#include "sdk.h"
#include <stdlib.h>


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


int main()
{
	//BDASM_Begin(MARKER_ATTRIBUTE_ENTIRE_FUNCTION, 0);

	printf("Hello Test. %llu\n", 0xFFEACC0DEF);
	int meme = other_routine();

	printf("Result was %d\n", meme);
	system("pause");


	return meme;
}