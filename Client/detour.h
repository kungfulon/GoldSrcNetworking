#ifndef DETOUR_H
#define DETOUR_H
#pragma once

class IDetour
{
public:
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual void* CreateHook(void* addr, void* hookFunc) = 0;
    virtual bool EnableHook(void* hook) = 0;
    virtual bool DisableHook(void* hook) = 0;
    virtual void DestroyHook(void* hook) = 0;
};

extern IDetour *detour;

bool HookIAT(CSysModule* module, const char* importModule, const char* name, uint16 ordinal, void* hookFunc);

#endif // DETOUR_H
