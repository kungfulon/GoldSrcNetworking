#include "interface.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <capstone/capstone.h>
#include <unordered_map>

#include "detour.h"

static uint8* ScanPattern(uint8* start, int size, const uint8* pattern, int patternLen) {
    auto comp = [](uint8* i, const uint8* pattern, int patternLen) {
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

uint8* ScanPattern(CSysModule* module, const uint8* pattern, int patternLen) {
    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((uint8*)module + dosHeader->e_lfanew);
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        if (!(sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) ||
            !(sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }
        auto* p = ScanPattern((uint8*)module + sectionHeader->VirtualAddress, sectionHeader->Misc.VirtualSize, pattern, patternLen);
        if (p != nullptr) {
            return p;
        }
    }
    return nullptr;
}

struct TrampolineRegion {
    uint8* base;
    uint8* cur;
};

static csh cs;
static TrampolineRegion trampolineRegion;

bool InitializeDetour() {
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs) != CS_ERR_OK) {
        return false;
    }

    auto mem = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) {
        return false;
    }

    trampolineRegion.base = trampolineRegion.cur = (uint8*)mem;
    return true;
}

void ShutdownDetour() {
    VirtualFree(trampolineRegion.base, 0, MEM_RELEASE);
    cs_close(&cs);
}

struct PatchInfo {
    void* addr;
    uint8 original[5];
};

static std::unordered_map<void*, PatchInfo> patchInfo;

static void memcpyRWX(void *dst, void *src, size_t size) {
    DWORD oldProtect;
    VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(dst, src, size);
    VirtualProtect(dst, size, oldProtect, &oldProtect);
}

static void generateJMP(void* fn, void* target, uint8* out) {
    out[0] = '\xE9';
    *(uint32*)(out + 1) = (uint32)target - (uint32)fn - 5;
}

void* InstallHook(void* addr, void* hookFunc) {
    PatchInfo pi;
    pi.addr = addr;
    memcpy(pi.original, addr, sizeof(pi.original));
    
    const uint8* code = (uint8*)addr;
    size_t size = 32;
    uint64 address = (uint64)addr;
    cs_insn* ins = cs_malloc(cs);
    uint8* trampoline = trampolineRegion.cur;
    
    while (size > 27) {
        cs_disasm_iter(cs, &code, &size, &address, ins);
        
        switch (ins->bytes[0]) {
        case 0xE8u:
        case 0xE9u:
            generateJMP(trampolineRegion.cur, (void*)(code + *(uint32*)(ins->bytes + 1)), trampolineRegion.cur);
            trampolineRegion.cur[0] = ins->bytes[0];
            trampolineRegion.cur += 5;
            break;
        case 0xEBu:
            generateJMP(trampolineRegion.cur, (void*)(code + ins->bytes[1]), trampolineRegion.cur);
            trampolineRegion.cur += 5;
            break;
        default:
            memcpy(trampolineRegion.cur, ins->bytes, ins->size);
            trampolineRegion.cur += ins->size;
        }
    }

    generateJMP(trampolineRegion.cur, (void*)code, trampolineRegion.cur);
    trampolineRegion.cur += 5;

    uint8 patched[5];
    generateJMP(addr, hookFunc, patched);
    memcpyRWX(addr, patched, sizeof(patched));

    cs_free(ins, 1);
    return trampoline;
}

void UninstallHook(void* hook) {
    if (patchInfo.count(hook) == 0) {
        return;
    }

    const auto& pi = patchInfo[hook];
    memcpyRWX(pi.addr, (void*)pi.original, sizeof(pi.original));
    patchInfo.erase(hook);
}
