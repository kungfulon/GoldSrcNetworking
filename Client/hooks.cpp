#include <interface.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include <stddef.h>

#include <detour.h>
#include <steam/steam_api.h>
#include <steam/isteamclient012.h>

enum netadrtype_t {
    NA_UNUSED = 0,
    NA_LOOPBACK,
    NA_BROADCAST,
    NA_IP,
    NA_IPX,
    NA_BROADCAST_IPX,
};

typedef struct netadr_s {
    netadrtype_t type;
    unsigned __int8 ip[4];
    unsigned __int8 ipx[10];
    unsigned __int16 port;
} netadr_t;

static constexpr const BYTE stringToAdrPattern[] =
{ 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x56, 0x8B, 0x75, 0x08, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x56, 0xE8, 0x9B, 0x1F, 0xFC, 0xFF, 0x83, 0xC4, 0x08, 0x85, 0xC0, 0x74, 0x42 };

static constexpr const BYTE adrToStringPattern[] =
{ 0x55, 0x8B, 0xEC, 0x6A, 0x40, 0x6A, 0x00, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0x2F, 0x22, 0xFC, 0xFF, 0x8B, 0x45, 0x08, 0x83, 0xC4, 0x0C, 0x83, 0xF8, 0x01, 0x75, 0x1B };

static ISteamClient012* steamClient;
static ISteamNetworkingMessages* networkingMessages;

class P2PCallbacks  {
public:
    STEAM_CALLBACK(P2PCallbacks, OnSessionRequest, SteamNetworkingMessagesSessionRequest_t);
} *p2pCallbacks;

void P2PCallbacks::OnSessionRequest(SteamNetworkingMessagesSessionRequest_t *param) {
    networkingMessages->AcceptSessionWithUser(param->m_identityRemote);
}

typedef int (WSAAPI* tsendto)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
static tsendto _sendto;

int WSAAPI SendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    auto* addr = (const sockaddr_in*)to;
    if (addr->sin_port != htons(1)) {
        return _sendto(s, buf, len, flags, to, tolen);
    }

    // Only support individual for now.
    CSteamID steamID;
    steamID.Set(addr->sin_addr.S_un.S_addr, k_EUniversePublic, k_EAccountTypeIndividual);
    SteamNetworkingIdentity identity;
    identity.SetSteamID(steamID);
    auto result = networkingMessages->SendMessageToUser(identity, buf, len, k_nSteamNetworkingSend_Reliable | k_nSteamNetworkingSend_AutoRestartBrokenSession, 0);
    if (result != k_EResultOK) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    WSASetLastError(0);
    return len;
}

typedef int (WSAAPI* trecvfrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
static trecvfrom _recvfrom;

int WSAAPI RecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    SteamNetworkingMessage_t* msg;
    if (networkingMessages->ReceiveMessagesOnChannel(0, &msg, 1) != 1) {
        return _recvfrom(s, buf, len, flags, from, fromlen);
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
    addr->sin_port = htons(1);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
    memcpy(buf, msg->GetData(), msgLen);
    msg->Release();
    WSASetLastError(0);
    return msgLen;
}

typedef bool (*tSteamAPI_Init)();
static tSteamAPI_Init _SteamAPI_Init;

bool SteamInit() {
    if (!_SteamAPI_Init()) {
        return false;
    }

    auto steamApiModule = Sys_LoadModule("steam_api.dll");
    auto getSteamClient = (ISteamClient012 * (*)())Sys_GetProcAddress(steamApiModule, "SteamClient");
    steamClient = getSteamClient();
    networkingMessages = (ISteamNetworkingMessages*)steamClient->GetISteamGenericInterface(SteamAPI_GetHSteamUser(), SteamAPI_GetHSteamPipe(), STEAMNETWORKINGMESSAGES_INTERFACE_VERSION);
    p2pCallbacks = new P2PCallbacks;
    return true;
}

typedef void (*tSteamAPI_Shutdown)();
static tSteamAPI_Shutdown _SteamAPI_Shutdown;

void SteamShutdown() {
    if (p2pCallbacks != nullptr) {
        delete p2pCallbacks;
        p2pCallbacks = nullptr;
    }

    _SteamAPI_Shutdown();
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
    a->port = htons(1);
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
        if (port == 1) {
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

void SetupLibraryHooks() {
    _sendto = (tsendto)InstallHook(sendto, SendTo);
    _recvfrom = (trecvfrom)InstallHook(recvfrom, RecvFrom);
    _SteamAPI_Init = (tSteamAPI_Init)InstallHook(SteamAPI_Init, SteamInit);
    _SteamAPI_Shutdown = (tSteamAPI_Shutdown)InstallHook(SteamAPI_Shutdown, SteamShutdown);
}

void SetupEngineHooks(CSysModule* engineModule) {
    auto stringToAdrAddr = ScanPattern(engineModule, stringToAdrPattern, sizeof(stringToAdrPattern));
    if (stringToAdrAddr != nullptr) {
        _NET_StringToAdr = (tNET_StringToAdr)InstallHook(stringToAdrAddr, NET_StringToAdr);
    }

    auto adrToStringAddr = ScanPattern(engineModule, adrToStringPattern, sizeof(adrToStringPattern));
    if (adrToStringAddr != nullptr) {
        _NET_AdrToString = (tNET_AdrToString)InstallHook(adrToStringAddr, NET_AdrToString);
    }
}
