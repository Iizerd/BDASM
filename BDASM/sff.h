#ifndef __SHELLCODE_FILE_FORMAT_H
#define __SHELLCODE_FILE_FORMAT_H

#include <Windows.h>
#include <stdio.h>

#define SHELLCODE_FILE_MAGIC 'lCcS'

// Structures for dissassembling the shellcode file.
typedef struct _CLASS_DESCRIPTOR
{
	ULONG Magic;
	ULONG FunctionCount;
	ULONG TotalFileSize;
} CLASS_DESCRIPTOR, * PCLASS_DESCRIPTOR;

typedef struct _SHELLCODE_FUNC_DESCRIPTOR
{
	ULONG Offset;
	ULONG Size;
} SHELLCODE_FUNC_DESCRIPTOR, * PSHELLCODE_FUNC_DESCRIPTOR;

typedef struct _DECOMP_FILE
{
	CLASS_DESCRIPTOR Class;
	SHELLCODE_FUNC_DESCRIPTOR Functions[1];
} DECOMP_FILE, * PDECOMP_FILE;

inline BOOLEAN SffVerify(PDECOMP_FILE File)
{
	return (File->Class.Magic == SHELLCODE_FILE_MAGIC);
}

inline VOID SffDbgPrint(PDECOMP_FILE File)
{
	printf("Magic: \'%c%c%c%c\'\n",
		((PCHAR)&File->Class.Magic)[0],
		((PCHAR)&File->Class.Magic)[1],
		((PCHAR)&File->Class.Magic)[2],
		((PCHAR)&File->Class.Magic)[3]);

	printf("FunctionCount: %u\n", File->Class.FunctionCount);
	printf("File Size:     0x%X\n", File->Class.TotalFileSize);

	for (int i = 0; i < File->Class.FunctionCount; i++)
	{
		printf("  Function[%d]:\n", i);
		printf("\tSize:   0x%X\n", File->Functions[i].Size);
		printf("\tOffset: 0x%X\n", File->Functions[i].Offset);
	}
}


#endif
