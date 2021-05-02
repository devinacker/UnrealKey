#pragma once

#include <Windows.h>

class Breakpoint
{
public:
	enum Type
	{
		Exec = 0x0,
		Write = 0x1,
		ReadWrite = 0x3,

		Size1 = 0x0,
		Size2 = 0x4,
		Size4 = 0xC,
		Size8 = 0x8,

		AccessMask = 0x3,
		SizeMask = 0xC
	};

	Breakpoint(DWORD tid, void* addr, UCHAR type);
	~Breakpoint();

	bool set(void* addr, UCHAR type);
	bool enable();
	bool disable();

	bool   enabled() const { return m_nIndex >= 0 && m_nIndex < 4; }
	void*  addr() const    { return m_pAddr; }
	UCHAR  type() const    { return m_nType; }
	UCHAR  access() const  { return m_nType & AccessMask; }
	UCHAR  size() const    { return m_nType & SizeMask; }
	HANDLE thread() const  { return m_hThread; }

private:
	HANDLE m_hThread;
	void*  m_pAddr;
	UCHAR  m_nType;
	CHAR   m_nIndex;
};
