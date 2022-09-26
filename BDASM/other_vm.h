#pragma once

#include <cstdint>

namespace ovm
{
	namespace vinst_fmt
	{
#pragma pack(push,1)

		// Describes a max of 2 registers of any size
		// Reg1 = Base & 0x3F
		// Reg2 = Base >> 6
		//
		struct two_reg_t
		{
			uint16_t reg1 : 6;
			uint16_t reg2 : 6;
			uint16_t pad : 4;
		};
		static_assert(sizeof(two_reg_t) == 2);
		
		// Describes an index scale combo
		// index = Base & 0xF
		// scale = Base >> 4
		//
		struct index_scale_t
		{
			uint8_t index : 4;
			uint8_t scale : 2;
			uint8_t pad : 2;
		};
		static_assert(sizeof(index_scale_t) == 1);

		//struct imm


#pragma pack(pop)
	}


}