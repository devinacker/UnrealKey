# UnrealKey

UnrealKey is a tool for automatically finding the AES-256 decryption keys for Unreal Engine 4 encrypted pak files.

Pass the path to a game's executable as an argument to UnrealKey.exe, and it will launch the game and attempt to detect the loading and decryption of encrypted pak files. If successful, the decryption key(s) will appear in the output, usually within a few seconds of launching the game.

### Example output

```
[11976] starting TetrisEffect.exe
[ 9604] starting "C:\Program Files\Epic Games\TetrisEffect\TetrisEffect/Binaries/Win64/TetrisEffect-Win64-Shipping.exe" TetrisEffect
[ 9604] Reading pak info for \\?\C:\Program Files\Epic Games\TetrisEffect\TetrisEffect\Content\Paks\TetrisEffect-WindowsNoEditor.pak (encrypted)
[ 9604] Reading encrypted pak index for TetrisEffect-WindowsNoEditor.pak
[ 9604] Detected buffer->index copy successfully
[ 9604] Detected index decryption successfully, finding key now...
[ 9604] Key: 0x0635D5F4B20E2CF1708524223DB7F1C77E7C49C556C5B875A90132E88E91F734
[11976] process exited with code 0x0

Summary:
--------

File: \\?\C:\Program Files\Epic Games\TetrisEffect\TetrisEffect\Content\Paks\TetrisEffect-WindowsNoEditor.pak
Key:  0x0635D5F4B20E2CF1708524223DB7F1C77E7C49C556C5B875A90132E88E91F734
```

### Limitations

Currently, only 64-bit Windows games are supported.

Games using Steam DRM should work as long as the game is actually in your Steam library, but you will most likely need to add a valid `steam_appid.txt` file (containing the game's app ID) to the game executable's directory to prevent the game from trying to re-launch itself through the Steam client.

Games using anti-cheat software will most likely _not_ work, since this tool doesn't make any attempt to circumvent it.

This has not been tested with a large number of games yet. If you have a UE4 game that uses encrypted pak files and UnrealKey doesn't seem to detect the decryption keys correctly, please open an issue and include the entire output from the program (but also please be sure to note the above as well).

### License

UnrealKey uses code from ![minhook](https://github.com/TsudaKageyu/minhook) (2-clause BSD license) and ![tiny-AES-c](https://github.com/kokke/tiny-AES-c) (public domain).

All other code is released under the MIT license. See COPYING.txt for details.
