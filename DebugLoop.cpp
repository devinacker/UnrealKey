#include <cstdio>
#include <vector>
#include <string>

#include "Breakpoint.h"
#include "DebugLoop.h"
#include "common.h"

extern "C"
{
#include "aes.h"
}

#define PID_DEBUG(fmt, pid, ...) printf("[%5d] " fmt, pid, __VA_ARGS__)

static union
{
	WCHAR g_pathw[1024];
	CHAR g_path[1024];
};

struct FoundKey
{
	std::wstring fileName;
	UCHAR key[AES_KEYLEN];
};

static std::vector<FoundKey> g_foundKeys;
static std::vector<HANDLE> g_namedPipes;

static PipeMessage g_indexData;
static bool g_running;

// ----------------------------------------------------------------------------
static void HandleNewProcess(DWORD pid, LPCWSTR filePath)
{
	bool ok = false;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	snprintf(g_path, sizeof(g_path), PIPE_NAME, pid);
	HANDLE hPipe = CreateNamedPipeA(g_path, PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT, 1,
		0, sizeof(PipeMessage), 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		PID_DEBUG("couldn't open named pipe (error 0x%x)\n", pid, GetLastError());
	}
	else
	{
		g_namedPipes.push_back(hPipe);

		PID_DEBUG("Starting %ws\n", pid, filePath);

		GetCurrentDirectoryW(MAX_PATH, g_pathw);
		std::wstring currentDir(g_pathw);

		GetModuleFileNameW(NULL, g_pathw, MAX_PATH);
		wcsrchr(g_pathw, L'\\')[1] = 0;
		SetCurrentDirectoryW(g_pathw);

		WIN32_FIND_DATAW findData = { 0 };
		hFile = FindFirstFileW(L".\\UnrealKey64.dll", &findData);
		wcscat_s(g_pathw, findData.cFileName);

		SetCurrentDirectoryW(currentDir.c_str());
	}

	if (hFile != INVALID_HANDLE_VALUE)
	{
		// got DLL path, load it in the remote process

		LPVOID procMem = VirtualAllocEx(hProcess, NULL, sizeof(g_pathw), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (WriteProcessMemory(hProcess, procMem, g_pathw, sizeof(g_pathw), NULL))
		{
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
				(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryW"),
				procMem, 0, NULL);

			if (hThread)
			{
				WaitForSingleObject(hThread, INFINITE);

				DWORD exitCode;
				if (GetExitCodeThread(hThread, &exitCode) && exitCode)
				{
					ok = true;
				}
				else
				{
					PID_DEBUG("Remote thread init error\n", pid);
				}

				CloseHandle(hThread);
			}
			else
			{
				PID_DEBUG("Couldn't start remote thread (error 0x%x)\n", pid, GetLastError());
			}
		}
		else
		{
			PID_DEBUG("Couldn't write to process memory (error 0x%x)\n", pid, GetLastError());
		}

		FindClose(hFile);
	}
	else
	{
		PID_DEBUG("Couldn't find UnrealKey64.dll\n", pid);
	}

	if (!ok)
	{
		// can't do anything useful here, just leave
		TerminateProcess(hProcess, 1);
	}

	CloseHandle(hProcess);
}

// ----------------------------------------------------------------------------
static void DebugOutputEvent(const DEBUG_EVENT& event)
{
	WORD len = min(sizeof(g_pathw), event.u.DebugString.nDebugStringLength);
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, event.dwProcessId);

	memset(g_pathw, 0, sizeof(g_pathw));
	if (ReadProcessMemory(hProcess, event.u.DebugString.lpDebugStringData, g_pathw, event.u.DebugString.nDebugStringLength, NULL))
	{
		if (event.u.DebugString.fUnicode)
		{
			PID_DEBUG("%ws", event.dwProcessId, g_pathw);
		}
		else
		{
			PID_DEBUG("%s", event.dwProcessId, g_path);
		}
	}

	CloseHandle(hProcess);
}

// ----------------------------------------------------------------------------
static void HandleIndexDataMessage(const PipeMessage& message)
{
	g_indexData = message;

	// Start debugging the remote process now
	if (DebugActiveProcess(message.pid))
	{
		// Set a hardware breakpoint on the first byte of index data that we're watching,
		// so that when it's copied out of the buffer into the actual index, we can
		// find out where the index is, and then put another breakpoint on that later.
		g_indexData.msgIndex.breakpoint = new Breakpoint(message.tid, message.msgIndex.indexAddr, Breakpoint::ReadWrite);
	}
	else
	{
		PID_DEBUG("Couldn't attach to process (error 0x%x)\n", message.pid, GetLastError());
	}
}

// ----------------------------------------------------------------------------
static bool HandleSteamAppIDMessage(const PipeMessage& message)
{
	if (GetEnvironmentVariableA("SteamAppID", g_path, sizeof(g_path)) > 0)
	{
		PID_DEBUG("Already tried to restart with SteamAppID once, aborting...\n", message.pid);
		PID_DEBUG("Make sure Steam is actually running.\n", message.pid);
		return false;
	}

	snprintf(g_path, sizeof(g_path), "%u", message.msgUInt);

	if (SetEnvironmentVariableA("SteamAppID", g_path))
	{
		PID_DEBUG("Set SteamAppID successfully, app will restart...\n", message.pid);
		return true;
	}

	PID_DEBUG("Couldn't set SteamAppID (error 0x%x)\n", message.pid, GetLastError());
	return false;
}

// ----------------------------------------------------------------------------
static bool BreakpointEvent(const DEBUG_EVENT& event, bool &detach)
{
	if (event.dwProcessId != g_indexData.pid
		|| event.dwThreadId != g_indexData.tid)
	{
		return false;
	}
	
	HANDLE hThread = g_indexData.msgIndex.breakpoint->thread();
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL; // get RIP, RSP, RSI and RDI

	GetThreadContext(hThread, &ctx);

	if (g_indexData.msgIndex.breakpoint->access() == Breakpoint::ReadWrite)
	{
		// Data should be getting memmove'd out of the buffer into the real index now.
		// Check the source/dest registers and make sure we can determine where it's going,
		// then put a new breakpoint in the destination somewhere
		auto indexAddr = (DWORD64)g_indexData.msgIndex.indexAddr;

		if (ctx.Rsi >= indexAddr
			&& ctx.Rsi < indexAddr + g_indexData.msgIndex.readBufSize)
		{
			g_indexData.msgIndex.indexAddr = (void*)(ctx.Rdi - (ctx.Rsi - indexAddr));

			g_indexData.msgIndex.breakpoint->set((CHAR*)g_indexData.msgIndex.indexAddr + AES_BLOCKLEN - 1, Breakpoint::Write);

			PID_DEBUG("Detected buffer->index copy successfully\n", event.dwProcessId);
		}
		else
		{
			PID_DEBUG("Unexpected read out of buffer!\n", event.dwProcessId);
			PID_DEBUG("\tRIP=0x%p, RSI=0x%p, RDI=0x%p, buf=%p\n", event.dwProcessId,
				(void*)ctx.Rip, (void*)ctx.Rsi, (void*)ctx.Rdi, g_indexData.msgIndex.indexAddr);
		}
	}
	else if (g_indexData.msgIndex.breakpoint->access() == Breakpoint::Write)
	{
		// One full block of data in the index buffer has been decrypted now.
		// We have both the encrypted and decrypted data, and the key should be on the stack
		PID_DEBUG("Detected index decryption successfully, finding key now...\n", event.dwProcessId);

		UCHAR decrypted[AES_BLOCKLEN];
		HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, event.dwProcessId);
		if (ReadProcessMemory(hProcess, g_indexData.msgIndex.indexAddr, decrypted, sizeof(decrypted), NULL))
		{
			UCHAR encrypted[AES_BLOCKLEN];
			UCHAR possibleKey[AES_KEYLEN];
			AES_ctx aes;
				
			// start crawling the stack and see if we find anything good
			bool foundKey = false;
			for (auto sp = ctx.Rsp; !foundKey && sp < ctx.Rsp + 0x200; sp += sizeof(void*))
			{
				memcpy(encrypted, g_indexData.msgIndex.indexData, AES_BLOCKLEN);
				ReadProcessMemory(hProcess, (void*)sp, possibleKey, AES_KEYLEN, NULL);

				AES_init_ctx(&aes, possibleKey);
				AES_ECB_decrypt(&aes, encrypted);
				if (!memcmp(encrypted, decrypted, AES_BLOCKLEN))
				{
					PID_DEBUG("Key: 0x", event.dwProcessId);
					for (int i = 0; i < AES_KEYLEN; i++)
					{
						printf("%02X", possibleKey[i]);
					}
					printf("\n");

					foundKey = true;

					auto &key = *g_foundKeys.insert(g_foundKeys.end(), FoundKey());
					key.fileName = g_indexData.msgIndex.filePath;
					memcpy(key.key, possibleKey, AES_KEYLEN);
				}
			}
			if (!foundKey)
			{
				PID_DEBUG("Couldn't find a valid key.\n", event.dwProcessId);
			}
		}
		else
		{
			PID_DEBUG("Reading process memory at %p failed!\n", event.dwProcessId, g_indexData.msgIndex.indexAddr);
		}
		CloseHandle(hProcess);

		// we're done, no more breakpoints
		delete g_indexData.msgIndex.breakpoint;
		g_indexData.msgIndex.breakpoint = NULL;
		g_indexData.pid = g_indexData.tid = 0;

		detach = true;
	}
	else
	{
		// ???
		return false;
	}

	return true;
}

// ----------------------------------------------------------------------------
static BOOL WINAPI CtrlHandler(DWORD type)
{
	if (type == CTRL_C_EVENT)
	{
		printf("Ctrl-C received, stopping...\n");
		g_running = false;
		return TRUE;
	}

	return FALSE;
}

// ----------------------------------------------------------------------------
static bool StartProcess(LPCWSTR appPath, HANDLE hJob, PROCESS_INFORMATION& pi)
{
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);

	if (!CreateProcessW(appPath, NULL, NULL, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi))
	{
		printf("couldn't launch %ws (error 0x%x)\n", appPath, GetLastError());
		return false;
	}

	HandleNewProcess(pi.dwProcessId, appPath);
	AssignProcessToJobObject(hJob, pi.hProcess);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);

	return true;
}

// ----------------------------------------------------------------------------
int DebugLoop(LPCWSTR appPath)
{
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = { 0 };
	HANDLE hJob = CreateJobObjectW(NULL, NULL);
	jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo));

	PROCESS_INFORMATION pi = { 0 };

	printf("Starting the game now.\nClose the game or press Ctrl-C to stop.\n\n");

	if (!StartProcess(appPath, hJob, pi))
		return 1;

	g_running = true;
	int rc = 0;
	bool restart = false;
	DEBUG_EVENT event;
	PipeMessage message;
	DWORD dwTemp;

	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	while (g_running)
	{
		if (GetExitCodeProcess(pi.hProcess, &dwTemp)
			&& dwTemp != STILL_ACTIVE)
		{
			PID_DEBUG("process exited with code 0x%x\n", pi.dwProcessId, dwTemp);
			
			// if we want to try to restart with a Steam App ID set (or something), do that now
			if (restart)
			{
				restart = false;

				if (StartProcess(appPath, hJob, pi))
					continue;
				else
					rc = 1;
			}

			g_running = false;
			break;
		}

		for (int i = 0; i < g_namedPipes.size(); i++)
		{
			if (ReadFile(g_namedPipes[i], &message, sizeof(message), &dwTemp, NULL))
			{
				switch (message.msgType)
				{
				case StringMessage:
					PID_DEBUG("%ws\n", message.pid, message.msgString);
					break;

				case NewProcessMessage:
					HandleNewProcess(message.msgProcess.pid, message.msgProcess.filePath);
					break;

				case IndexDataMessage:
					HandleIndexDataMessage(message);
					break;

				case SteamAppIDMessage:
					restart = HandleSteamAppIDMessage(message);
					break;
				}

				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, message.tid);
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
			else if (GetLastError() == ERROR_BROKEN_PIPE)
			{
				CloseHandle(g_namedPipes[i]);
				g_namedPipes[i] = g_namedPipes.back();
				g_namedPipes.pop_back();
				i--;
			}
		}
		while (WaitForDebugEvent(&event, 50))
		{
			bool handled = false;
			bool detach = false;

			switch (event.dwDebugEventCode)
			{
			case CREATE_PROCESS_DEBUG_EVENT:
				handled = true;
				CloseHandle(event.u.CreateProcessInfo.hFile);
				break;

			case LOAD_DLL_DEBUG_EVENT:
				handled = true;
				CloseHandle(event.u.LoadDll.hFile);
				break;

#ifdef HANDLE_DEBUG_OUT
			case OUTPUT_DEBUG_STRING_EVENT:
				handled = true;
				DebugOutputEvent(event);
				break;
#endif

			case EXCEPTION_DEBUG_EVENT:
				switch (event.u.Exception.ExceptionRecord.ExceptionCode)
				{
				case EXCEPTION_BREAKPOINT:
				case 0x406d1388: // thread rename notification
					handled = true;
					break;

				case EXCEPTION_SINGLE_STEP:
					handled = BreakpointEvent(event, detach);
				default:
					break;
				}
				break;

			case EXIT_PROCESS_DEBUG_EVENT:
				handled = true;
				PID_DEBUG("process exited with code 0x%x\n", event.dwProcessId, event.u.ExitProcess.dwExitCode);
				break;

			default:
				break;
			}

			ContinueDebugEvent(event.dwProcessId, event.dwThreadId, handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED);

			if (detach)
				DebugActiveProcessStop(event.dwProcessId);
		}
	}

	// Clean up and show any keys that were found
	CloseHandle(pi.hProcess);
	CloseHandle(hJob);
	
	printf("\nSummary:\n--------\n\n");

	if (g_foundKeys.empty())
	{
		printf("No valid keys were found.\n");
	}
	else for (auto &key : g_foundKeys)
	{
		printf("File: %ws\n", key.fileName.c_str());
		printf("Key:  0x");
		for (int i = 0; i < AES_KEYLEN; i++)
		{
			printf("%02X", key.key[i]);
		}
		printf("\n\n");
	}

	return rc;
}
