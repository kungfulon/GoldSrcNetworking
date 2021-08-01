# GoldSrcNetworking

P2P networking support for GoldSrc games.

## Building

Use Visual Studio 2015 build tools to build the project.

## Installation

- Copy `Client.exe` that was built before to your GoldSrc game folder.
- Additionally, the file can be renamed to `<mod>.exe` (for instance, `cstrike.exe`) so you can launch the mod directly.

Always run the game with the custom EXE file to use P2P networking.

Use `connect <STEAMID>`, for example `connect STEAM_0:0:1111110` to connect to other player's listen server.

If you get `LAN servers are restricted to class C` error, the host must type `sv_lan 0` into their console.

Note that you cannot connect to other players that are not using this project.

## Will I get VAC banned?

Maybe, maybe not. If you just use this to play with friends then should be OK since listen server does not enable VAC by default.

If you want to play on public servers, launch the game through Steam (it will run original `hl.exe`) will be safe.

## License

This project is licensed under MIT License.

This project uses Half-Life SDK. The license is available at https://github.com/ValveSoftware/halflife/blob/master/LICENSE.

This project uses Steamworks SDK. The license is available at https://partner.steamgames.com/documentation/sdk_access_agreement. 

This project uses Capstone Disassembly Engine. The license is available at https://github.com/aquynh/capstone/blob/master/LICENSE.TXT.
