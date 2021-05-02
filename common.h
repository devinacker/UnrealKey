#pragma once
#include <Windows.h>
#include "Breakpoint.h"

#define PIPE_NAME "\\\\.\\pipe\\UnrealKey\\%d"

enum PipeMessageType
{
	StringMessage,
	NewProcessMessage,
	IndexDataMessage,
};

struct PipeProcessData
{
	WCHAR filePath[MAX_PATH];
	DWORD pid, flags;
};

struct PipeIndexData
{
	WCHAR filePath[MAX_PATH];
	void *indexAddr;
	DWORD readBufSize;
	UCHAR indexData[16];
	// only used by exception handler
	Breakpoint *breakpoint;
};

struct PipeMessage
{
	DWORD pid, tid;
	WORD msgType;
	union
	{
		WCHAR msgString[1024];
		PipeProcessData msgProcess;
		PipeIndexData msgIndex;
	};
};
