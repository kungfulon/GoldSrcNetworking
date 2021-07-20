#include "interface.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

#include "detour.h"

static BYTE* ScanPattern(BYTE* start, int size, const BYTE* pattern, int patternLen) {
    auto comp = [](BYTE* i, const BYTE* pattern, int patternLen) {
        for (auto j = 0; j < patternLen; ++j) {
            if (pattern[j] == 0xCC) {
                continue;
            }
            if (i[j] != pattern[j]) {
                return false;
            }
        }
        return true;
    };
    for (auto* i = start; i + patternLen <= start + size; ++i) {
        if (comp(i, pattern, patternLen)) {
            return i;
        }
    }
    return nullptr;
}

BYTE *ScanPattern(CSysModule* module, const BYTE* pattern, int patternLen) {
    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + dosHeader->e_lfanew);
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        if (!(sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) ||
            !(sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }
        auto* p = ScanPattern((BYTE*)module + sectionHeader->VirtualAddress, sectionHeader->Misc.VirtualSize, pattern, patternLen);
        if (p != nullptr) {
            return p;
        }
    }
    return nullptr;
}

Hook::Hook(void* addr, void* hookFunc) : addr(addr) {
    auto diff = (UINT32)hookFunc - (UINT32)addr - 5;
    memcpy(unpatchedBytes, addr, sizeof(unpatchedBytes));
    patchedBytes[0] = '\xe9';
    *(UINT32*)(patchedBytes + 1) = diff;
}

void Hook::Enable() {
    DWORD oldProtect;
    VirtualProtect(addr, sizeof(patchedBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(addr, patchedBytes, sizeof(patchedBytes));
    VirtualProtect(addr, sizeof(patchedBytes), oldProtect, &oldProtect);
}

void Hook::Disable() {
    DWORD oldProtect;
    VirtualProtect(addr, sizeof(unpatchedBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(addr, unpatchedBytes, sizeof(unpatchedBytes));
    VirtualProtect(addr, sizeof(unpatchedBytes), oldProtect, &oldProtect);
}
