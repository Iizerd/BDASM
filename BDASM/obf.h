
#include "obf_structures.h"


#include "mba.h"

void meme()
{
	dasm::routine_t<addr_width::x64> routine;
	obf::routine_t<addr_width::x64> obfr(routine);
	obf::context_t<addr_width::x64> ctx;
	ctx.bin = nullptr;
	ctx.linker = nullptr;
	obfr.mutation_pass<obf::mba_t<>>(ctx);
}