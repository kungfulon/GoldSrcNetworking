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

static Hook* hookSendTo;
static Hook* hookRecvFrom;
static Hook* hookSteamInit;
static Hook* hookSteamShutdown;
static Hook* hookStringToAdr;
static Hook* hookAdrToString;
static ISteamClient012* steamClient;
static ISteamNetworkingMessages* networkingMessages;

class P2PCallbacks  {
public:
    STEAM_CALLBACK(P2PCallbacks, OnSessionRequest, SteamNetworkingMessagesSessionRequest_t);
} *p2pCallbacks;

void P2PCallbacks::OnSessionRequest(SteamNetworkingMessagesSessionRequest_t *param) {
    networkingMessages->AcceptSessionWithUser(param->m_identityRemote);
}

int WSAAPI SendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    auto* addr = (const sockaddr_in*)to;
    if (addr->sin_port != htons(1)) {
        hookSendTo->Disable();
        int result = sendto(s, buf, len, flags, to, tolen);
        hookSendTo->Enable();
        return result;
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

int WSAAPI RecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    SteamNetworkingMessage_t* msg;
    if (networkingMessages->ReceiveMessagesOnChannel(0, &msg, 1) != 1) {
        hookRecvFrom->Disable();
        int result = recvfrom(s, buf, len, flags, from, fromlen);
        if (result != SOCKET_ERROR) {
            WSASetLastError(0);
        }
        hookRecvFrom->Enable();
        return result;
    }
    if (len < (int)msg->GetSize()) {
        msg->Release();
        WSASetLastError(WSAEMSGSIZE);
        return SOCKET_ERROR;
    }
    auto* addr = (sockaddr_in*)from;
    addr->sin_family = AF_INET;
    addr->sin_addr.S_un.S_addr = msg->m_identityPeer.GetSteamID().GetAccountID();
    addr->sin_port = htons(1);
    memset(addr->sin_zero, 0, sizeof(addr->sin_zero));
    memcpy(buf, msg->GetData(), msg->GetSize());
    msg->Release();
    WSASetLastError(0);
    return msg->GetSize();
}

bool SteamInit() {
    hookSteamInit->Disable();
    bool result = SteamAPI_Init();
    hookSteamInit->Enable();

    if (!result) {
        return false;
    }

    auto steamApiModule = Sys_LoadModule("steam_api.dll");
    auto getSteamClient = (ISteamClient012 * (*)())Sys_GetProcAddress(steamApiModule, "SteamClient");
    steamClient = getSteamClient();
    networkingMessages = (ISteamNetworkingMessages*)steamClient->GetISteamGenericInterface(SteamAPI_GetHSteamUser(), SteamAPI_GetHSteamPipe(), STEAMNETWORKINGMESSAGES_INTERFACE_VERSION);
    p2pCallbacks = new P2PCallbacks;
    return true;
}

void SteamShutdown() {
    if (p2pCallbacks != nullptr) {
        delete p2pCallbacks;
        p2pCallbacks = nullptr;
    }

    hookSteamShutdown->Disable();
    SteamAPI_Shutdown();
    hookSteamShutdown->Enable();
}

int NET_StringToAdr(char* s, netadr_t* a) {
    if (strncmp(s, "STEAM_", 6)) {
        hookStringToAdr->Disable();
        auto stringToAdr = (int (*)(char*, netadr_t*))hookStringToAdr->Addr();
        int result = stringToAdr(s, a);
        hookStringToAdr->Enable();
        return result;
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
    hookSendTo = new Hook(sendto, SendTo);
    hookSendTo->Enable();

    hookRecvFrom = new Hook(recvfrom, RecvFrom);
    hookRecvFrom->Enable();

    hookSteamInit = new Hook(SteamAPI_Init, SteamInit);
    hookSteamInit->Enable();

    hookSteamShutdown = new Hook(SteamAPI_Shutdown, SteamShutdown);
    hookSteamShutdown->Enable();
}

void SetupEngineHooks(CSysModule* engineModule) {
    auto stringToAdrAddr = ScanPattern(engineModule, stringToAdrPattern, sizeof(stringToAdrPattern));
    if (stringToAdrAddr != nullptr) {
        hookStringToAdr = new Hook(stringToAdrAddr, NET_StringToAdr);
        hookStringToAdr->Enable();
    }

    auto adrToStringAddr = ScanPattern(engineModule, adrToStringPattern, sizeof(adrToStringPattern));
    if (adrToStringAddr != nullptr) {
        hookAdrToString = new Hook(adrToStringAddr, NET_AdrToString);
        hookAdrToString->Enable();
    }
}
