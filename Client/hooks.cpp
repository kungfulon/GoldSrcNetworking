#include <interface.h>
#include <steam/steam_api.h>
#include <netadr.h>

#include <WinSock2.h>

#include "detour.h"

static constexpr uint16 P2P_PORT = 1;

static constexpr uint16 RECVFROM_ORDINAL = 17;
static constexpr uint16 SENDTO_ORDINAL = 20;

static constexpr const uint8 NET_StringToAdrPattern[] =
{ 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x56, 0x8B, 0x75, 0x08, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x56, 0xE8, 0x9B, 0x1F, 0xFC, 0xFF, 0x83, 0xC4, 0x08, 0x85, 0xC0, 0x74, 0x42 };

static constexpr const uint8 NET_AdrToStringPattern[] =
{ 0x55, 0x8B, 0xEC, 0x6A, 0x40, 0x6A, 0x00, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0x2F, 0x22, 0xFC, 0xFF, 0x8B, 0x45, 0x08, 0x83, 0xC4, 0x0C, 0x83, 0xF8, 0x01, 0x75, 0x1B };

static constexpr const uint8 SV_CheckIPRestrictionsPattern[] =
{ 0x55, 0x8B, 0xEC, 0xD9, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0xD8, 0x1D, 0xCC, 0xCC, 0xCC, 0xCC, 0x53, 0x56, 0x57, 0xDF, 0xE0, 0xF6, 0xC4, 0x44, 0x8B, 0x45 };

class SteamAPIContext  {
public:
    bool Init();
    void Clear();

    ISteamClient* SteamClient() { return m_pSteamClient; }
    ISteamNetworkingMessages* SteamNetworkingMessages() { return  m_pSteamNetworkingMessages; }

    STEAM_CALLBACK(SteamAPIContext, OnSessionRequest, SteamNetworkingMessagesSessionRequest_t);

private:
    ISteamClient* m_pSteamClient;
    ISteamNetworkingMessages* m_pSteamNetworkingMessages;
} steam;

bool SteamAPIContext::Init() {
    auto steamClientModule = Sys_LoadModule("steamclient.dll");
    auto steamClientFactory = Sys_GetFactory(steamClientModule);
  
    m_pSteamClient = (ISteamClient*)steamClientFactory(STEAMCLIENT_INTERFACE_VERSION, nullptr);
    if (m_pSteamClient == nullptr) {
        return false;
    }

    HSteamUser hSteamUser = SteamAPI_GetHSteamUser();
    HSteamPipe hSteamPipe = SteamAPI_GetHSteamPipe();

    m_pSteamNetworkingMessages = (ISteamNetworkingMessages*)SteamClient()->GetISteamGenericInterface(hSteamUser, hSteamPipe, STEAMNETWORKINGMESSAGES_INTERFACE_VERSION);
    if (m_pSteamNetworkingMessages == nullptr) {
        return false;
    }

    return true;
}

void SteamAPIContext::Clear() {
    memset(this, 0, sizeof(*this));
}

void SteamAPIContext::OnSessionRequest(SteamNetworkingMessagesSessionRequest_t *param) {
    steam.SteamNetworkingMessages()->AcceptSessionWithUser(param->m_identityRemote);
}

int WSAAPI SendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    auto* addr = (const sockaddr_in*)to;
    if (addr->sin_port != htons(P2P_PORT)) {
        return sendto(s, buf, len, flags, to, tolen);
    }

    // Only support individual for now.
    CSteamID steamID;
    steamID.Set(addr->sin_addr.S_un.S_addr, k_EUniversePublic, k_EAccountTypeIndividual);
    SteamNetworkingIdentity identity;
    identity.SetSteamID(steamID);
    auto result = steam.SteamNetworkingMessages()->SendMessageToUser(identity, buf, len, k_nSteamNetworkingSend_Unreliable | k_nSteamNetworkingSend_AutoRestartBrokenSession, 0);
    if (result != k_EResultOK) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    WSASetLastError(0);
    return len;
}

int WSAAPI RecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    SteamNetworkingMessage_t* msg;
    if (steam.SteamNetworkingMessages()->ReceiveMessagesOnChannel(0, &msg, 1) != 1) {
        return recvfrom(s, buf, len, flags, from, fromlen);
    }

    int msgLen = (int)msg->GetSize();
    if (len < msgLen) {
        msg->Release();
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }

    auto* addr = (sockaddr_in*)from;
    addr->sin_family = AF_INET;
    addr->sin_addr.S_un.S_addr = msg->m_identityPeer.GetSteamID().GetAccountID();
    addr->sin_port = htons(P2P_PORT);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
    memcpy(buf, msg->GetData(), msgLen);
    msg->Release();
    WSASetLastError(0);
    return msgLen;
}

bool SteamInit() {
    if (!SteamAPI_Init()) {
        return false;
    }

    return steam.Init();
}

void SteamShutdown() {
    steam.Clear();

    SteamAPI_Shutdown();
}

typedef int (*tNET_StringToAdr)(char* s, netadr_t* a);
static tNET_StringToAdr _NET_StringToAdr;

int NET_StringToAdr(char* s, netadr_t* a) {
    if (strncmp(s, "STEAM_", 6)) {
        return _NET_StringToAdr(s, a);
    }

    EUniverse universe;
    uint32 authServer;
    uint32 accountNumber;
    sscanf(s, "STEAM_%u:%u:%u", &universe, &authServer, &accountNumber);

    // Only support individual for now.
    CSteamID steamID;
    steamID.Set((accountNumber << 1) | authServer, k_EUniversePublic, k_EAccountTypeIndividual);
    *(uint32*)a->ip = steamID.GetAccountID();
    a->port = htons(P2P_PORT);
    a->type = NA_IP;
    return 1;
}

typedef char* (*tNET_AdrToString)(netadr_t a);
static tNET_AdrToString _NET_AdrToString;

char* NET_AdrToString(netadr_t a) {
    static char buf[64];
    memset(buf, 0, sizeof(buf));
    
    if (a.type == NA_LOOPBACK) {
        _snprintf(buf, sizeof(buf), "loopback");
        return buf;
    }

    int port = ntohs(a.port);
    if (a.type == NA_IP) {
        if (port == P2P_PORT) {
            uint32 accountID = *(uint32*)a.ip;
            _snprintf(buf, sizeof(buf), "STEAM_%u:%u:%u", k_EUniversePublic, accountID & 1, accountID >> 1);
        }
        else {
            _snprintf(buf, sizeof(buf), "%i.%i.%i.%i:%i", a.ip[0], a.ip[1], a.ip[2], a.ip[3], port);
        }
        return buf;
    }
    
    _snprintf(buf, sizeof(buf), "%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%i",
        a.ipx[0], a.ipx[1], a.ipx[2], a.ipx[3], a.ipx[4],
        a.ipx[5], a.ipx[6], a.ipx[7], a.ipx[8], a.ipx[9],
        port);
    return buf;
}

typedef int (*tSV_CheckIPRestrictions)(netadr_t* adr, int nAuthProtocol);
static tSV_CheckIPRestrictions _SV_CheckIPRestrictions;

int SV_CheckIPRestrictions(netadr_t* adr, int nAuthProtocol) {
    if (adr->type == NA_IP && adr->port == htons(P2P_PORT)) {
        return true;
    }

    return _SV_CheckIPRestrictions(adr, nAuthProtocol);
}

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

static uint8* ScanPattern(CSysModule* module, const uint8* pattern, int patternLen) {
    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((uint8*)module + dosHeader->e_lfanew);
    auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (auto i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader)
    {
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

bool InitializeHooks(CSysModule* engineModule) {
    if (!detour->Initialize()) {
        return false;
    }

    if (!HookIAT(engineModule, "wsock32.dll", nullptr, RECVFROM_ORDINAL, RecvFrom) ||
        !HookIAT(engineModule, "wsock32.dll", nullptr, SENDTO_ORDINAL, SendTo) ||
        !HookIAT(engineModule, "steam_api.dll", "SteamAPI_Init", 0, SteamInit) ||
        !HookIAT(engineModule, "steam_api.dll", "SteamAPI_Shutdown", 0, SteamShutdown)) {
        return false;
    }

    auto NET_StringToAdrAddr = ScanPattern(engineModule, NET_StringToAdrPattern, sizeof(NET_StringToAdrPattern));
    if (NET_StringToAdrAddr == nullptr) {
        return false;
    }
    _NET_StringToAdr = (tNET_StringToAdr)detour->CreateHook(NET_StringToAdrAddr, NET_StringToAdr);
    detour->EnableHook(_NET_StringToAdr);

    auto NET_AdrToStringAddr = ScanPattern(engineModule, NET_AdrToStringPattern, sizeof(NET_AdrToStringPattern));
    if (NET_AdrToStringAddr == nullptr) {
        return false;
    }
    _NET_AdrToString = (tNET_AdrToString)detour->CreateHook(NET_AdrToStringAddr, NET_AdrToString);
    detour->EnableHook(_NET_AdrToString);

    auto SV_CheckIPRestrictionsAddr = ScanPattern(engineModule, SV_CheckIPRestrictionsPattern, sizeof(SV_CheckIPRestrictionsPattern));
    if (SV_CheckIPRestrictionsAddr == nullptr) {
        return false;
    }
    _SV_CheckIPRestrictions = (tSV_CheckIPRestrictions)detour->CreateHook(SV_CheckIPRestrictionsAddr, SV_CheckIPRestrictions);
    detour->EnableHook(_SV_CheckIPRestrictions);

    return true;
}

void ShutdownHooks(CSysModule* engineModule)
{
    HookIAT(engineModule, "wsock32.dll", nullptr, RECVFROM_ORDINAL, recvfrom);
    HookIAT(engineModule, "wsock32.dll", nullptr, SENDTO_ORDINAL, sendto);
    HookIAT(engineModule, "steam_api.dll", "SteamAPI_Init", 0, SteamAPI_Init);
    HookIAT(engineModule, "steam_api.dll", "SteamAPI_Shutdown", 0, SteamAPI_Shutdown);

    detour->Shutdown();
}
