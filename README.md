# UnrealKey

UnrealKey is a tool for automatically finding the AES-256 decryption keys for Unreal Engine 4 encrypted pak files.

Pass the path to a game's executable as an argument to UnrealKey.exe, and it will launch the game and attempt to detect the loading and decryption of encrypted pak files. If successful, the decryption key(s) will appear in the output, usually within a few seconds of launching the game.

__This project is a proof of concept and is not being actively developed or maintained.__

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

Games using Steam DRM should work (_without_ needing to manually create a `steam_appid.txt` file), as long as the Steam client is open and logged in (and the game is actually in your library). If you're having trouble with a particular game, try running it through Steamless first.

Games using anti-cheat software will most likely _not_ work, since this tool doesn't make any attempt to circumvent it.

### License

UnrealKey uses code from [minhook](https://github.com/TsudaKageyu/minhook) (2-clause BSD license) and [tiny-AES-c](https://github.com/kokke/tiny-AES-c) (public domain).

All other code is released under the MIT license. See COPYING.txt for details.
