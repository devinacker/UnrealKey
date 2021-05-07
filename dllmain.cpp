#include <Windows.h>
#include <cstdio>
#include <cstdarg>
#include <vector>

#include <MinHook.h>

#include "common.h"

#pragma pack(1)
struct PakHeaderOld // not all of it, just the stuff we need
{
	CHAR bEncrypted;
	DWORD magic;
	DWORD version;
	UINT64 indexOffset, indexSize;
};

struct PakHeader
{
	GUID guid;
	PakHeaderOld data;
};
#pragma pack()

static const DWORD PakMagic = 0x5a6f12e1;

// track encrypted index locations that we've found
struct PakIndex
{
	HANDLE hFile;
	UINT64 indexOffset;
	GUID guid;
};

std::vector<PakIndex> g_pakIndexes;

static HANDLE g_hPipe;

// WinAPI function hooks
auto orig_CreateProcessW = CreateProcessW;
auto orig_ShellExecuteA = ShellExecuteA;
auto orig_ShellExecuteW = ShellExecuteW;
auto orig_ReadFile = ReadFile;
NTSTATUS (*orig_ZwSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);

// ----------------------------------------------------------------------------
static void SendPipeMessage(PipeMessage& msg)
{
	msg.pid = GetCurrentProcessId();
	msg.tid = GetCurrentThreadId();

	DWORD dummy;
	if (WriteFile(g_hPipe, &msg, sizeof(msg), &dummy, NULL))
	{
		// wait for launcher to handle message
		SuspendThread(GetCurrentThread());
	}
}

// ----------------------------------------------------------------------------
static void SendStringMessage(const WCHAR *str, ...)
{
	PipeMessage msg;
	msg.msgType = StringMessage;

	va_list va;
	va_start(va, str);
	_vsnwprintf_s(msg.msgString, sizeof(msg.msgString) / sizeof(WCHAR), str, va);
	va_end(va);

	SendPipeMessage(msg);
}

// ----------------------------------------------------------------------------
static void CheckPakHeader(HANDLE hFile, const PakHeaderOld *header, const GUID *guid = NULL)
{
	// found a potential pak header
	WCHAR path[MAX_PATH];
	GetFinalPathNameByHandleW(hFile, path, MAX_PATH, 0);

	if (header != NULL && header->bEncrypted)
	{
		SendStringMessage(L"Reading pak info for %ws (encrypted)", path);

		PakIndex index = { 0 };
		index.hFile = hFile;
		index.indexOffset = header->indexOffset;

		if (guid)
		{
			index.guid = *guid;
			StringFromGUID2(*guid, path, MAX_PATH);
			SendStringMessage(L"key GUID is %ws", path);
		}

		g_pakIndexes.push_back(index);
	}
	else
	{
		SendStringMessage(L"Reading pak info for %ws (not encrypted, ignoring)", path);
	}
}

// ----------------------------------------------------------------------------
static BOOL WINAPI hook_CreateProcessW(LPCWSTR name, LPWSTR cmdLine, LPSECURITY_ATTRIBUTES procAttr, LPSECURITY_ATTRIBUTES threadAttr,
	BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
	// create suspended version of process, signal it to the launcher
	if (orig_CreateProcessW(name, cmdLine, procAttr, threadAttr, inherit,
		flags | CREATE_SUSPENDED, env, dir, si, pi))
	{
		PipeMessage msg;
		msg.msgType = NewProcessMessage;

		if (name)
			wcsncpy_s(msg.msgProcess.filePath, name, MAX_PATH);
		else
			wcsncpy_s(msg.msgProcess.filePath, cmdLine, MAX_PATH);

		msg.msgProcess.pid = pi->dwProcessId;
		msg.msgProcess.flags = flags;
		SendPipeMessage(msg);

		// if the process wasn't already supposed to be suspended, unsuspend it now
		if (!(flags & CREATE_SUSPENDED))
		{
			ResumeThread(pi->hThread);
		}

		return TRUE;
	}

	return FALSE;
}

// ----------------------------------------------------------------------------
static void RunWithSteamAppID(UINT appID)
{
	SendStringMessage(L"Tried to launch Steam w/ app ID %u", appID);
	
	PipeMessage msg;
	msg.msgType = SteamAppIDMessage;
	msg.msgUInt = appID;
	SendPipeMessage(msg);
}

// ----------------------------------------------------------------------------
static HINSTANCE WINAPI hook_ShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParams, LPCSTR lpDir, INT nShowCmd)
{
	UINT appID;

	if (lpOperation && lpFile
		&& !strcmp(lpOperation, "open")
		&& sscanf_s(lpFile, "steam://run/%u", &appID) == 1)
	{
		RunWithSteamAppID(appID);
		return 0;
	}

	return orig_ShellExecuteA(hwnd, lpOperation, lpFile, lpParams, lpDir, nShowCmd);
}

// ----------------------------------------------------------------------------
static HINSTANCE WINAPI hook_ShellExecuteW(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile, LPCWSTR lpParams, LPCWSTR lpDir, INT nShowCmd)
{
	UINT appID;

	if (lpFile && lpParams
		&& wcsstr(lpFile, L"steam.exe")
		&& swscanf_s(lpParams, L"steam://run/%u", &appID) == 1)
	{
		RunWithSteamAppID(appID);
		return 0;
	}

	return orig_ShellExecuteW(hwnd, lpOperation, lpFile, lpParams, lpDir, nShowCmd);
}

// ----------------------------------------------------------------------------
static BOOL WINAPI hook_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nSize, LPDWORD lpSize, LPOVERLAPPED lpOverlapped)
{
	PakHeader* header = (PakHeader*)lpBuffer;
	PakHeaderOld* headerOld = (PakHeaderOld*)lpBuffer;

	BOOL ok = orig_ReadFile(hFile, lpBuffer, nSize, lpSize, lpOverlapped);

	if (!ok && lpOverlapped && GetLastError() == ERROR_IO_PENDING)
	{
		// wait for read to finish
		ok = GetOverlappedResult(hFile, lpOverlapped, lpSize, true);
	}

	if (ok)
	{
		if (*lpSize >= sizeof(PakHeader) && header->data.magic == PakMagic)
		{
			CheckPakHeader(hFile, &header->data, &header->guid);
		}
		else if (*lpSize >= sizeof(PakHeaderOld) && headerOld->magic == PakMagic)
		{
			CheckPakHeader(hFile, headerOld);
		}
		else if (*lpSize >= sizeof(DWORD) && *(DWORD*)lpBuffer == PakMagic)
		{
			CheckPakHeader(hFile, NULL);
		}
		else for (auto &index : g_pakIndexes)
		{
			// see if we're reading the encrypted index for one of the pak files we found earlier
			if (hFile == index.hFile
				&& lpOverlapped
				&& (UINT32)lpOverlapped->Offset == (UINT32)index.indexOffset
				&& (UINT32)lpOverlapped->OffsetHigh == (index.indexOffset >> 32))
			{
				PipeMessage msg;
				msg.msgType = IndexDataMessage;

				GetFinalPathNameByHandleW(hFile, msg.msgIndex.filePath, MAX_PATH, 0);
				msg.msgIndex.indexAddr = lpBuffer;
				msg.msgIndex.readBufSize = nSize;
			//	msg.msgIndex.guid = index.guid;
				memcpy(msg.msgIndex.indexData, lpBuffer, sizeof(msg.msgIndex.indexData));

			//	SendStringMessage(L"Reading encrypted pak index to 0x%p for %ws", lpBuffer, msg.msgIndex.filePath);
				SendStringMessage(L"Reading encrypted pak index for %ws", wcsrchr(msg.msgIndex.filePath, L'\\') + 1);
			//	SendStringMessage(L"Buffer size is 0x%x", nSize);
				SendPipeMessage(msg);
			}
		}
	}

	return ok;
}

// ----------------------------------------------------------------------------
static NTSTATUS hook_ZwSetInformationThread(HANDLE hThread, ULONG infoClass, PVOID info, ULONG infoLength)
{
	// ignore ThreadHideFromDebugger
	if (infoClass == 0x11)
		return TRUE;

	return orig_ZwSetInformationThread(hThread, infoClass, info, infoLength);
}

// ----------------------------------------------------------------------------
static BOOL Init()
{
	CHAR pipeName[MAX_PATH];

	snprintf(pipeName, sizeof(pipeName), PIPE_NAME, GetCurrentProcessId());
	g_hPipe = CreateFileA(pipeName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
	if (g_hPipe != INVALID_HANDLE_VALUE)
	{
		DWORD mode = PIPE_READMODE_MESSAGE;
		SetNamedPipeHandleState(g_hPipe, &mode, NULL, NULL);
	}
	else
	{
		return FALSE;
	}

	MH_STATUS hookStatus = MH_Initialize();
	if (!hookStatus)
	{
		MH_CreateHook(CreateProcessW, hook_CreateProcessW, (LPVOID*)&orig_CreateProcessW);
		MH_CreateHook(ShellExecuteA, hook_ShellExecuteA, (LPVOID*)&orig_ShellExecuteA);
		MH_CreateHook(ShellExecuteW, hook_ShellExecuteW, (LPVOID*)&orig_ShellExecuteW);
		MH_CreateHook(ReadFile, hook_ReadFile, (LPVOID*)&orig_ReadFile);
		MH_CreateHook(GetProcAddress(GetModuleHandleA("ntdll"), "ZwSetInformationThread"),
			hook_ZwSetInformationThread, (LPVOID*)&orig_ZwSetInformationThread);

		hookStatus = MH_EnableHook(MH_ALL_HOOKS);
		if (!hookStatus)
		{
		//	SendStringMessage(L"Initialized hooks");
		}
		else
		{
			SendStringMessage(L"MinHook enable failed: %hs", MH_StatusToString(hookStatus));
			return FALSE;
		}
	}
	else
	{
		SendStringMessage(L"MinHook init failed: %hs", MH_StatusToString(hookStatus));
		return FALSE;
	}

	return TRUE;
}

// ----------------------------------------------------------------------------
static void DeInit()
{
	CloseHandle(g_hPipe);
	MH_Uninitialize();
}

// ----------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		return Init();
		break;

	case DLL_PROCESS_DETACH:
		DeInit();
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	
	return TRUE;
}

