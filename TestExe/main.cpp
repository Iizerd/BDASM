

#include <stdio.h>


#include "sdk.h"



int main()
{
	BDASM_Begin(MARKER_ATTRIBUTE_ENTIRE_FUNCTION, 0);

	printf("Hello Test. %llu\n", 0xFFEACC0DEF);

	BDASM_End();
	return 1;
}