#pragma once


#include "dasm.h"

namespace obf
{
	enum class pass_status_t
	{
		// Complete and total failure that means we need to scrub the whole process
		//
		critical_failure,

		// Failure but its ok, the routine is still intact and we can proceed with other routines
		//
		failure,
		
		// 
		//
		success,
	};

	template<addr_width::type Addr_width = addr_width::x64>
	struct context_t
	{
		dasm::linker_t* linker;
		pex::binary_t<Addr_width>* bin;
	};

	template<addr_width::type Addr_width = addr_width::x64>
	class routine_t
	{
	public:
		dasm::routine_t<Addr_width>& m_routine;

	public:

		routine_t(dasm::routine_t<Addr_width>& routine)
			: m_routine(routine)
		{}

		template<typename Pass_type, typename... Params>
		pass_status_t mutation_pass(context_t<Addr_width>& ctx, Params... params)
		{
			return Pass_type::pass(m_routine, ctx, params...);
		}
	};
}

