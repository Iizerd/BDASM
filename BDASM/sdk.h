#pragma once

#include <intrin.h>

// Tells the obfuscator that it can generate instructions that modify
// themselves or others in the current group.
//
#define MARKER_ATTRIBUTE_SINGLE_THREAD			(1 << 0)

// Tells the obfuscator that the code is only executed once, and can 
// be destroyed after executed. Probably done with rip relative instructions.
// This implies MARKER_ATTRIBUTE_SINGLE_THREAD
//
#define MARKER_ATTRIBUTE_EXECUTED_ONCE			((1 << 1) | MARKER_ATTRIBUTE_SINGLE_THREAD)

// Tells the obfuscator that it is to extend the group backwards until the 
// start of the current function. This is useful because the markers will
// appear in code AFTER the prologue, meaning they would not be within the 
// group.
//
#define MARKER_ATTRIBUTE_EXTEND_TO_FUNC_START	(1 << 2)

// Same as above, but extends the group to the end instead.
// 
#define MARKER_ATTRIBUTE_EXTEND_TO_FUNC_END		(1 << 3)

// Tells the obfuscator that the entire function the BDASM_Begin appears
// in is to be treated as one group and obfuscated.
// This will ignore BDASM_End macros so you dont need to put one.
// Implies MARKER_ATTRIBUTE_EXTEND_TO_FUNC_START and MARKER_ATTRIBUTE_EXTEND_TO_FUNC_END
// 
#define MARKER_ATTRIBUTE_ENTIRE_FUNCTION		((1<<4) | MARKER_ATTRIBUTE_EXTEND_TO_FUNC_START | MARKER_ATTRIBUTE_EXTEND_TO_FUNC_END)



// Mutate 
//
#define MARKER_OBF_TYPE_MUTATE					(1 << 0)

// Hide instructions that manipulate RSP
//
#define MARKER_OBF_HIDE_RSP_ACTIONS				(1 << 1)

#define BDASM_BEGIN_INST_COUNT				5
#define BDASM_Begin(						\
	MarkerAttributes,						\
	ObfuscationSettings						\
		)									\
		{									\
			__nop();						\
			__debugbreak();					\
			_xabort(MarkerAttributes);		\
			_xabort(ObfuscationSettings);	\
			__nop();						\
		}

#define BDASM_END_INST_COUNT				4
#define BDASM_End()							\
		{									\
			__nop();						\
			__debugbreak();					\
			__debugbreak();					\
			__nop();						\
		}



