#pragma once

BYTE* ScanPattern(CSysModule* module, const BYTE* pattern, int patternLen);

class Hook {
public:
    Hook(void* addr, void* hookFunc);
    void Enable();
    void Disable();
    void* Addr() {
        return addr;
    };

private:
    void* addr;
    unsigned char unpatchedBytes[5];
    unsigned char patchedBytes[5];
};
