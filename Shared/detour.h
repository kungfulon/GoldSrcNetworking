#pragma once

#include "archtypes.h"

uint8* ScanPattern(CSysModule* module, const uint8* pattern, int patternLen);
bool InitializeDetour();
void ShutdownDetour();
void* InstallHook(void* addr, void* hookFunc);
void UninstallHook(void* hook);
