#include <ICommandLine.h>
#include <FileSystem.h>
#include "hooks.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <io.h>

#include <ienginelauncherapi.h>

static constexpr const char* fileSystemDll = "filesystem_stdio.dll";
static constexpr const char* defaultExeName = "hl.exe";

static char gameDir[MAX_PATH];
static IFileSystem* fileSystem;

static bool GetExecutablePath(char* out, int outSize) {
    return GetModuleFileNameA((HINSTANCE)GetModuleHandleA(nullptr), out, outSize) != 0;
}

static const char* GetEngineDll() {
    // TODO: Choose sw.dll and hw.dll
    return "hw.dll";
}

static CSysModule* LoadFilesystemModule(const char* root, bool runningSteam) {
    auto module = Sys_LoadModule(fileSystemDll);
    if (module) {
        return module;
    }

    if (strchr(root, ';')) {
        MessageBoxA(0, "Game cannot be run from directories containing the semicolon character (';')", "Fatal Error", MB_OK | MB_ICONERROR);
        return nullptr;
    }

    _finddata_t findData;
    auto findHandle = _findfirst(fileSystemDll, &findData);
    if (findHandle == -1) {
        MessageBoxA(0, "Could not find filesystem dll to load.", "Fatal Error", MB_OK | MB_ICONERROR);
    }
    else {
        MessageBoxA(0, "Could not load filesystem dll.\nFileSystem crashed during construction.", "Fatal Error", MB_OK | MB_ICONERROR);
        _findclose(findHandle);
    }

    return nullptr;
}

static bool FallbackVideoMode() {
    // TODO: Registry
    return MessageBoxA(NULL, "The specified video mode is not supported.\nThe game will now run in gl mode.", "Video mode change failure", MB_OKCANCEL | MB_ICONWARNING) == 1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    auto mutex = CreateMutexA(nullptr, FALSE, "ValveHalfLifeLauncherMutex");
    if (mutex) {
        GetLastError();
    }

    auto waitResult = WaitForSingleObject(mutex, 0);
    if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_ABANDONED) {
        MessageBoxA(0, "Could not launch game.\nOnly one instance of this game can be run at a time.", "Error", MB_OK | MB_ICONERROR);
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 0), &wsaData);
    CommandLine()->CreateCmdLine(GetCommandLineA());
    bool runningSteam = CommandLine()->CheckParm("-steam") != nullptr;
    
    char baseDir[256];
    GetExecutablePath(baseDir, sizeof(baseDir));
    auto exeName = strrchr(baseDir, '\\');
    *exeName++ = '\0';
    if (_stricmp(exeName, defaultExeName) && CommandLine()->CheckParm("-game") == nullptr) {
        exeName[strlen(exeName) - 4] = '\0';
        CommandLine()->AppendParm("-game", exeName);
    }
    const char* game = nullptr;
    if (CommandLine()->CheckParm("-game", &game) != nullptr) {
        strncpy(gameDir, game, sizeof(gameDir));
    }
    else {
        strcpy(gameDir, "valve");
    }

    _unlink("mssv29.asi");
    _unlink("mssv12.asi");
    _unlink("mp3dec.asi");
    _unlink("opengl32.dll");

    // TODO: Registry

    SetupLibraryHooks();
    bool shouldRestart = false;
    do {
        auto fileSystemModule = LoadFilesystemModule(baseDir, runningSteam);
        if (fileSystemModule == nullptr) {
            break;
        }
        auto fileSystemFactory = Sys_GetFactory(fileSystemModule);
        fileSystem = (IFileSystem*)fileSystemFactory(FILESYSTEM_INTERFACE_VERSION, nullptr);
        fileSystem->Mount();
        fileSystem->AddSearchPath(baseDir, "ROOT");

        auto engineDll = GetEngineDll();
        auto engineModule = Sys_LoadModule(engineDll);
        if (engineModule == nullptr) {
            char msg[512];
            sprintf(msg, "Could not load %s.\nPlease try again at a later time.", engineDll);
            MessageBoxA(0, msg, "Fatal Error", 0x10u);
        }
        SetupEngineHooks(engineModule);

        int engineResult = ENGINE_RESULT_NONE;
        static char newCommandParams[2048];
        auto engineFactory = Sys_GetFactory(engineModule);
        if (engineFactory != nullptr) {
            auto engineLauncherAPI = (IEngineLauncherAPI*)engineFactory(VENGINE_LAUNCHER_API_VERSION, nullptr);
            if (engineLauncherAPI != nullptr) {
                engineResult = engineLauncherAPI->Run(hInstance, baseDir, CommandLine()->GetCmdLine(), newCommandParams, Sys_GetFactoryThis(), fileSystemFactory);
            }
        }

        switch (engineResult) {
        case ENGINE_RESULT_NONE:
            shouldRestart = false;
            break;
        case ENGINE_RESULT_RESTART:
            shouldRestart = true;
            break;
        case ENGINE_RESULT_UNSUPPORTEDVIDEO:
            shouldRestart = FallbackVideoMode();
            break;
        }

        CommandLine()->RemoveParm("-sw");
        CommandLine()->RemoveParm("-startwindowed");
        CommandLine()->RemoveParm("-windowed");
        CommandLine()->RemoveParm("-window");
        CommandLine()->RemoveParm("-full");
        CommandLine()->RemoveParm("-fullscreen");
        CommandLine()->RemoveParm("-soft");
        CommandLine()->RemoveParm("-software");
        CommandLine()->RemoveParm("-gl");
        CommandLine()->RemoveParm("-d3d");
        CommandLine()->RemoveParm("-w");
        CommandLine()->RemoveParm("-width");
        CommandLine()->RemoveParm("-h");
        CommandLine()->RemoveParm("-height");
        CommandLine()->RemoveParm("+connect");
        CommandLine()->SetParm("-novid", 0);
        if (strstr(newCommandParams, "-game")) {
            CommandLine()->RemoveParm("-game");
        }
        if (strstr(newCommandParams, "+load")) {
            CommandLine()->RemoveParm("+load");
        }
        CommandLine()->AppendParm(newCommandParams, nullptr);

        Sys_UnloadModule(engineModule);
        fileSystem->Unmount();
        Sys_UnloadModule(fileSystemModule);
    } while (shouldRestart);

    ReleaseMutex(mutex);
    CloseHandle(mutex);
    WSACleanup();
    return 0;
}