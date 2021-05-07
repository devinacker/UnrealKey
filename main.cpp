#include <windows.h>
#include <cstdio>

#include "DebugLoop.h"

int main()
{
	printf("UnrealKey v0.2.0 - " __DATE__ "\n");
	printf("https://github.com/devinacker/UnrealKey\n\n");

	int rc = 0;
	int argc = 0;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	
	if (argc < 2)
	{
		if (argv)
			printf("usage: %ws path_to_game_exe\n", argv[0]);
		rc = 1;
	}
	else
	{
		rc = DebugLoop(argv[1]);
	}

	LocalFree(argv);
	return rc;
}
