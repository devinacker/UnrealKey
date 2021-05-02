#include "Breakpoint.h"

// ----------------------------------------------------------------------------
Breakpoint::Breakpoint(DWORD tid, void* addr, UCHAR type)
{
	m_hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
	m_nIndex = -1;
	this->set(addr, type);
	this->enable();
}

// ----------------------------------------------------------------------------
Breakpoint::~Breakpoint()
{
	this->disable();
	CloseHandle(m_hThread);
}

// ----------------------------------------------------------------------------
bool Breakpoint::set(void* addr, UCHAR type)
{
	m_pAddr = addr;
	m_nType = type;

	if (this->enabled())
	{
		// update existing breakpoint
		return this->enable();
	}

	return true;
}

// ----------------------------------------------------------------------------
bool Breakpoint::enable()
{
	BOOL ok = false;

	SuspendThread(m_hThread);

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(m_hThread, &ctx))
	{
		ok = true;
		auto index = -1;

		if (this->enabled())        index = m_nIndex;
		else if (!(ctx.Dr7 & 0x01)) index = 0;
		else if (!(ctx.Dr7 & 0x04)) index = 1;
		else if (!(ctx.Dr7 & 0x10)) index = 2;
		else if (!(ctx.Dr7 & 0x40)) index = 3;

		switch (index)
		{
		default:
			ok = false;
			break;

		case 0:
			ctx.Dr0 = (DWORD64)m_pAddr;
			ctx.Dr7 &= 0xFFF0FFFC;
			ctx.Dr7 |= (m_nType << 16) | 0x01;
			break;

		case 1:
			ctx.Dr1 = (DWORD64)m_pAddr;
			ctx.Dr7 &= 0xFF0FFFF3;
			ctx.Dr7 |= (m_nType << 20) | 0x04;
			break;

		case 2:
			ctx.Dr2 = (DWORD64)m_pAddr;
			ctx.Dr7 &= 0xF0FFFFCF;
			ctx.Dr7 |= (m_nType << 24) | 0x10;
			break;

		case 3:
			ctx.Dr3 = (DWORD64)m_pAddr;
			ctx.Dr7 &= 0x0FFFFF3F;
			ctx.Dr7 |= (m_nType << 28) | 0x40;
			break;
		}

		ctx.Dr6 = 0;
		if (ok &= SetThreadContext(m_hThread, &ctx))
		{
			m_nIndex = index;
		}
	}

	ResumeThread(m_hThread);

	return ok;
}

// ----------------------------------------------------------------------------
bool Breakpoint::disable()
{
	BOOL ok = false;

	SuspendThread(m_hThread);

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(m_hThread, &ctx))
	{
		ok = true;

		switch (m_nIndex)
		{
		default:
			ok = false;
			break;

		case 0:
			ctx.Dr7 &= 0xFFF0FFFC;
			break;

		case 1:
			ctx.Dr7 &= 0xFF0FFFF3;
			break;

		case 2:
			ctx.Dr7 &= 0xF0FFFFCF;
			break;

		case 3:
			ctx.Dr7 &= 0x0FFFFF3F;
			break;
		}

		ctx.Dr6 = 0;
		if (ok &= SetThreadContext(m_hThread, &ctx))
		{
			m_nIndex = -1;
		}
	}

	ResumeThread(m_hThread);

	return ok;
}
