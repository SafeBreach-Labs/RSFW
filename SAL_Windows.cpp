#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <mswsock.h>
#include "SAL.h"
#include "debug.h"
extern "C" {
#include "../../funchook/include/funchook.h"
}

#pragma comment( lib, "ws2_32")

class AcceptArgs
{
public:
    PVOID        m_lpOutputBuffer;
    DWORD        m_dwReceiveDataLength;
    DWORD        m_dwLocalAddressLength;
    DWORD        m_dwRemoteAddressLength;
    AcceptArgs(PVOID lpOutputBuffer, DWORD dwReceiveDataLength, DWORD dwLocalAddressLength, DWORD dwRemoteAddressLength) : m_lpOutputBuffer(lpOutputBuffer), m_dwReceiveDataLength(dwReceiveDataLength), m_dwLocalAddressLength(dwLocalAddressLength), m_dwRemoteAddressLength(dwRemoteAddressLength)
    {}
    AcceptArgs() : m_lpOutputBuffer(NULL), m_dwReceiveDataLength(0), m_dwLocalAddressLength(0), m_dwRemoteAddressLength(0) {}
};

static std::map<socket_t, AbstractSocket*> stoad;

static std::map<LPOVERLAPPED, SOCKET> otos;
static std::map< LPOVERLAPPED, AcceptArgs> otoaa;


static void (*GetAcceptExSockaddrs_ptr)(
    PVOID    lpOutputBuffer,
    DWORD    dwReceiveDataLength,
    DWORD    dwLocalAddressLength,
    DWORD    dwRemoteAddressLength,
    sockaddr** LocalSockaddr,
    LPINT    LocalSockaddrLength,
    sockaddr** RemoteSockaddr,
    LPINT    RemoteSockaddrLength
    );

static BOOL(*AcceptEx_ptr)(
    SOCKET       sListenSocket,
    SOCKET       sAcceptSocket,
    PVOID        lpOutputBuffer,
    DWORD        dwReceiveDataLength,
    DWORD        dwLocalAddressLength,
    DWORD        dwRemoteAddressLength,
    LPDWORD      lpdwBytesReceived,
    LPOVERLAPPED lpOverlapped
    );

static int (WSAAPI* closesocket_ptr)(
    SOCKET s
    );


static SOCKET(WSAAPI* WSAAccept_ptr)(
    SOCKET          s,
    sockaddr* addr,
    LPINT           addrlen,
    LPCONDITIONPROC lpfnCondition,
    DWORD_PTR       dwCallbackData
    );

static int (WSAAPI* WSARecv_ptr) (
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesRecvd,
    LPDWORD                            lpFlags,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );

static SOCKET(WSAAPI* accept_ptr)(
    SOCKET   s,
    sockaddr* addr,
    int* addrlen
    );

static BOOL(WSAAPI* WSAGetOverlappedResult_ptr)(
    SOCKET          s,
    LPWSAOVERLAPPED lpOverlapped,
    LPDWORD         lpcbTransfer,
    BOOL            fWait,
    LPDWORD         lpdwFlags
    );

static BOOL(WINAPI* GetOverlappedResult_ptr)(
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    BOOL         bWait
    );

static BOOL(WINAPI* GetQueuedCompletionStatus_ptr)(
    HANDLE       CompletionPort,
    LPDWORD      lpNumberOfBytesTransferred,
    PULONG_PTR   lpCompletionKey,
    LPOVERLAPPED* lpOverlapped,
    DWORD        dwMilliseconds
    );

static BOOL(WINAPI* GetQueuedCompletionStatusEx_ptr)(
    _In_  HANDLE             CompletionPort,
    _Out_ LPOVERLAPPED_ENTRY lpCompletionPortEntries,
    _In_  ULONG              ulCount,
    _Out_ PULONG             ulNumEntriesRemoved,
    _In_  DWORD              dwMilliseconds,
    _In_  BOOL               fAlertable
    );




static BOOL AcceptEx_hook(
    SOCKET       sListenSocket,
    SOCKET       sAcceptSocket,
    PVOID        lpOutputBuffer,
    DWORD        dwReceiveDataLength,
    DWORD        dwLocalAddressLength,
    DWORD        dwRemoteAddressLength,
    LPDWORD      lpdwBytesReceived,
    LPOVERLAPPED lpOverlapped
)
{
    REPORT_HOOK("AcceptEx");

    DEBUG20(sprintf(str_buf, "RSFW: Socket: %lld: In AcceptEX!!!! dwReceiveDataLength=%d, lpOverlapped=%p!!!!\n", (__int64)sAcceptSocket, dwReceiveDataLength, lpOverlapped));
    if (dwReceiveDataLength > 0)
    {
        DEBUG0("AcceptEx() with dwReceiveDataLength>0 is not supported.");
        exit(0);
    }
    otos.insert(std::pair<LPOVERLAPPED, SOCKET>(lpOverlapped, sAcceptSocket));
    otoaa.insert(std::pair<LPOVERLAPPED, AcceptArgs>(lpOverlapped, AcceptArgs(lpOutputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength)));
    bool rv;
    rv = AcceptEx_ptr(sListenSocket, sAcceptSocket, lpOutputBuffer, dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength, lpdwBytesReceived, lpOverlapped);

    DWORD wsa_last_error = WSAGetLastError();
    DWORD last_error = GetLastError();
    if (rv || ((!rv) && (((GetLastError() == ERROR_IO_PENDING)) || ((GetLastError() == WSA_IO_PENDING)))))
    {
        //register_socket(sAcceptSocket);
    }
    else
    {
        otos.erase(lpOverlapped);
    }
    DEBUG20(sprintf(str_buf, "RSFW: Socket: %lld: RETURNING (rv=%d, last_error=%d)\n", (__int64)sAcceptSocket, rv, wsa_last_error));
    WSASetLastError(wsa_last_error);
    SetLastError(last_error);
    return rv;
}

static SOCKET WSAAPI WSAAccept_hook(
    SOCKET          s,
    sockaddr* addr,
    LPINT           addrlen,
    LPCONDITIONPROC lpfnCondition,
    DWORD_PTR       dwCallbackData
)
{
    REPORT_HOOK("WSAAccept");

    SOCKET rv;
    DEBUG20(sprintf(str_buf, "RSFW: in WSAAccept!!!\n"));
    rv = WSAAccept_ptr(s, addr, addrlen, lpfnCondition, dwCallbackData);
    bool ok = true;
    if (rv != INVALID_SOCKET)
    {
        //register_socket(s);
        sockaddr_any me;
        int me_size = sizeof(me);
        DWORD wsa_last_error = WSAGetLastError();
        DWORD last_error = GetLastError();
        if (getsockname(rv, (sockaddr*)&me, &me_size) != 0)
        {
            ok = false;
            DWORD error = WSAGetLastError();
            DEBUG0(sprintf(str_buf, "RSFW: LISTENING Socket " SOCK_FORMAT ", STRANGE - in WSAAccept, getsockname error %d\n", s, error));
        }
        else
        {
            DEBUG30(sprintf(str_buf, "RSFW: LISTENING Socket " SOCK_FORMAT ", WSAAccept, got length %d\n", s, me_size));
        }
        WSASetLastError(wsa_last_error);
        SetLastError(last_error);
        if (ok)
        {
            char from[100], to[100];
            ((sockaddr_any*)addr)->to_str(from);
            me.to_str(to);
            DEBUG10(sprintf(str_buf, "RSFW: LISTENING Socket " SOCK_FORMAT ", accepted connection %s -> %s as socket %lld.\n", s, from, to, (__int64)rv));
            stoad[rv] = SAL::gen_f(rv, &me, (sockaddr_any*)addr);
        }
    }
    else
    {
        //sprintf(str_buf,"RSFW: Socket " SOCK_FORMAT ", accept connection failed\n", s);
    }
    return rv;
}

static int WSAAPI WSARecv_hook(
    SOCKET                             s,
    LPWSABUF                           lpBuffers,
    DWORD                              dwBufferCount,
    LPDWORD                            lpNumberOfBytesRecvd,
    LPDWORD                            lpFlags,
    LPWSAOVERLAPPED                    lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
    REPORT_HOOK("WSARecv");

    DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ", trying to read %d buffers, first buffer len %d, overlapped=%p, completion=%p\n", s, dwBufferCount, lpBuffers[0].len, lpOverlapped, lpCompletionRoutine));
    if (lpOverlapped && (dwBufferCount == 1) && lpBuffers && (lpBuffers[0].len == 0))
    {
        // This is just using IOCP as a "wakeup service", without actually reading anything. The actual read is via a "blocking" WSARecv. So we can safely ignore this one...
        return WSARecv_ptr(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    }

    int rv;
    rv = WSARecv_ptr(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine); /* call the original recv(). */
    if (rv == 0)
    {
        if (stoad.find(s) != stoad.end())
        {
            if (lpNumberOfBytesRecvd == NULL)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Hmmm... lpNumberOfBytesRecvd==NULL\n", s));
                return rv;
            }
            if (lpBuffers == NULL)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Hmmm... lpBuffers==NULL\n", s));
                return rv;
            }
            DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Read %d bytes\n", s, *lpNumberOfBytesRecvd));
            unsigned int remaining = *lpNumberOfBytesRecvd;

            // We don't know what onRead will do, so we save the error state and restore it after all onRead's are done.
            DWORD wsa_last_error = WSAGetLastError();
            DWORD last_error = GetLastError();
            for (unsigned int i = 0; i < dwBufferCount; i++)
            {

                bool ok = stoad[s]->onRead(lpBuffers[i].buf, min(remaining, lpBuffers[i].len));
                if (!ok)
                {
                    closesocket_ptr(s);
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Erasing from stoad[] (supposedly it is closed now).\n", s));
                    delete stoad[s];
                    stoad.erase(s);
                    break;
                }
                remaining -= min(remaining, lpBuffers[i].len);
            }
            SetLastError(last_error);
            WSASetLastError(wsa_last_error);
        }
        else
        {
            DEBUG0(sprintf(str_buf, "RSFW: UNMANAGED Socket " SOCK_FORMAT ": Read %d bytes\n", s, *lpNumberOfBytesRecvd));
        }
    }
    else if (lpOverlapped && (WSAGetLastError() == WSA_IO_PENDING))
    {
        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Read successfully queued for IOCP\n", s));
    }
    else if ((lpOverlapped == NULL) && (WSAGetLastError() == WSAEWOULDBLOCK))
    {
        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": non-blocking WSARecv attempted, and no data is available.\n", s));
    }
    else
    {
        DWORD last_error = WSAGetLastError();
        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": read failed (rv=%d, lpOverlapped=%p, LastError=%d)\n", s, rv, lpOverlapped, last_error));
    }
    return rv;
}

static int WSAAPI closesocket_hook(
    SOCKET s
)
{
    REPORT_HOOK("closesocket");

    int rv;
    if (stoad.find(s) != stoad.end())
    {
        delete stoad[s];
        stoad.erase(s);
        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": closed\n", s));
    }
    else
    {
        DEBUG0(sprintf(str_buf, "RSFW: UNMANAGED Socket " SOCK_FORMAT ": closed\n", s));
    }
    rv = closesocket_ptr(s);
    return rv;
}

static SOCKET WSAAPI accept_hook(
    SOCKET   s,
    sockaddr* addr,
    int* addrlen
)
{
    REPORT_HOOK("accept");

    DEBUG20(sprintf(str_buf, "RSFW: in accept()!!!\n"));
    SOCKET rv = accept_ptr(s, addr, addrlen);
    return rv;
}

static BOOL WSAAPI WSAGetOverlappedResult_hook(
    SOCKET          s,
    LPWSAOVERLAPPED lpOverlapped,
    LPDWORD         lpcbTransfer,
    BOOL            fWait,
    LPDWORD         lpdwFlags
)
{
    REPORT_HOOK("WSAGetOverlappedResult");

    bool rv;
    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": WSAGetOverlappedResult called, overlapped=%p, wait=%d\n", s, lpOverlapped, fWait));
    rv = WSAGetOverlappedResult_ptr(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags);
    return rv;
}

static BOOL WINAPI GetOverlappedResult_hook(
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    BOOL         bWait
)
{
    REPORT_HOOK("GetOverlappedResult");

    bool rv;
    DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetOverlappedResult called, overlapped=%p, lpNumberOfBytesTransferred=%p, wait=%d\n", (socket_t)hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait));
    rv = GetOverlappedResult_ptr(hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);

    DWORD wsa_last_error = WSAGetLastError();
    DWORD last_error = GetLastError();
    if (rv)
    {
        if (lpNumberOfBytesTransferred != NULL)
        {
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetOverlappedResult returned %d bytes.\n", (socket_t)hFile, *lpNumberOfBytesTransferred));
        }
        if (otoaa.find(lpOverlapped) != otoaa.end())
        {
            if (otos.find(lpOverlapped) == otos.end())
            {
                DEBUG30(sprintf(str_buf, "RSFW: WARNING: overlapped found in otoaa, BUT NOT in otos!\n"));
            }
            SOCKET s = otos[lpOverlapped];
            if (stoad.find(s) == stoad.end())
            {
                if ((lpNumberOfBytesTransferred == NULL) || (*lpNumberOfBytesTransferred == 0))
                {
                    sockaddr_any* me = NULL;
                    sockaddr_any* peer = NULL;
                    int size_me = 0, size_peer = 0;
                    AcceptArgs& aa = otoaa[lpOverlapped];
                    DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": About to call GetAcceptExSockaddrs()\n", s));
                    GetAcceptExSockaddrs_ptr(aa.m_lpOutputBuffer, aa.m_dwReceiveDataLength, aa.m_dwLocalAddressLength, aa.m_dwRemoteAddressLength, (sockaddr**)&me, &size_me, (sockaddr**)&peer, &size_peer);
                    DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned %p (%d) %p (%d)\n", s, me, size_me, peer, size_peer));
                    if (me && peer)
                    {
                        DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned non NULL pointers - this is good\n", s));
                    }
                    else
                    {
                        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned NULL pointer(s) %p, %p - this is BAD\n", s, me, peer));
                    }
                    char from[100], to[100];
                    peer->to_str(from);
                    me->to_str(to);
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Connection Established: %s -> %s\n", s, from, to));
                    //stoad.insert(pair<SOCKET, SockDesc>(s, SockDesc(s, me, peer)));
                    stoad[s] = SAL::gen_f(s, me, peer);
                }
                else
                {
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": WTF?! getting data for the socket, the socket is not yet open\n", s));
                }
                //otoaa.erase(lpCompletionPortEntries[i].lpOverlapped);
            }
            else
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": WTF?! AcceptEx returned, but the socket is already open\n", s));
            }
            otos.erase(lpOverlapped);
        }
    }
    else
    {
        DEBUG20(sprintf(str_buf, "RSFW: GetOverlappedResult - FAILED\n"));
    }

    WSASetLastError(wsa_last_error);
    SetLastError(last_error);
    return rv;
}

static BOOL WINAPI GetQueuedCompletionStatus_hook(
    HANDLE       CompletionPort,
    LPDWORD      lpNumberOfBytesTransferred,
    PULONG_PTR   lpCompletionKey,
    LPOVERLAPPED* lpOverlapped,
    DWORD        dwMilliseconds
)
{
    REPORT_HOOK("GetQueuedCompletionStatus");

    bool rv;
    rv = GetQueuedCompletionStatus_ptr(CompletionPort, lpNumberOfBytesTransferred, lpCompletionKey, lpOverlapped, dwMilliseconds);
    DWORD wsa_last_error = WSAGetLastError();
    DWORD last_error = GetLastError();
    if (rv)
    {
        DEBUG20(sprintf(str_buf, "RSFW: GetQueuedCompletionStatus with CompletionPort=%p, pOverlapped=%p, overlapped=%p\n", CompletionPort, lpOverlapped, *lpOverlapped));
        if (otoaa.find(*lpOverlapped) != otoaa.end())
        {
            if (otos.find(*lpOverlapped) == otos.end())
            {
                DEBUG30(sprintf(str_buf, "RSFW: WARNING: overlapped found in otoaa, BUT NOT in otos!\n"));
            }
            SOCKET s = otos[*lpOverlapped];
            if (stoad.find(s) == stoad.end())
            {
                if ((lpNumberOfBytesTransferred == NULL) || (*lpNumberOfBytesTransferred == 0))
                {
                    sockaddr_any* me = NULL;
                    sockaddr_any* peer = NULL;
                    int size_me = 0, size_peer = 0;
                    AcceptArgs& aa = otoaa[*lpOverlapped];
                    DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": About to call GetAcceptExSockaddrs()\n", s));
                    GetAcceptExSockaddrs_ptr(aa.m_lpOutputBuffer, aa.m_dwReceiveDataLength, aa.m_dwLocalAddressLength, aa.m_dwRemoteAddressLength, (sockaddr**)&me, &size_me, (sockaddr**)&peer, &size_peer);
                    DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned %p (%d) %p (%d)\n", s, me, size_me, peer, size_peer));
                    if (me && peer)
                    {
                        DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned non NULL pointers - this is good\n", s));
                    }
                    else
                    {
                        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned NULL pointer(s) %p, %p - this is BAD\n", s, me, peer));
                    }
                    char from[100], to[100];
                    peer->to_str(from);
                    me->to_str(to);
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Connection Established: %s -> %s\n", s, from, to));
                    //stoad.insert(pair<SOCKET, SockDesc>(s, SockDesc(s, me, peer)));
                    stoad[s] = SAL::gen_f(s, me, peer);
                }
                else
                {
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": WTF?! getting data for the socket, the socket is not yet open\n", s));
                }
                //otoaa.erase(lpCompletionPortEntries[i].lpOverlapped);
            }
            else
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": WTF?! GetQueuedCompletionStatus returned, but the socket is already open\n", s));
            }
            otos.erase(*lpOverlapped);
        }
    }
    else
    {
        DEBUG20(sprintf(str_buf, "RSFW: GetQueuedCompletionStatus with CompletionPort=%p - FAILED\n", CompletionPort));
    }

    WSASetLastError(wsa_last_error);
    SetLastError(last_error);

    return rv;
}

static BOOL WINAPI GetQueuedCompletionStatusEx_hook(
    _In_  HANDLE             CompletionPort,
    _Out_ LPOVERLAPPED_ENTRY lpCompletionPortEntries,
    _In_  ULONG              ulCount,
    _Out_ PULONG             ulNumEntriesRemoved,
    _In_  DWORD              dwMilliseconds,
    _In_  BOOL               fAlertable
)
{
    REPORT_HOOK("GetQueuedCompletionStatusEx");

    bool rv;
    DEBUG20(sprintf(str_buf, "RSFW: GetQueuedCompletionStatusEx with CompletionPort=%p, %d entries\n", CompletionPort, ulCount));
    rv = GetQueuedCompletionStatusEx_ptr(CompletionPort, lpCompletionPortEntries, ulCount, ulNumEntriesRemoved, dwMilliseconds, fAlertable);
    DEBUG30(sprintf(str_buf, "      Actual entries: %d (rv=%d)\n", *ulNumEntriesRemoved, rv));
    if (rv)
    {
        if (lpCompletionPortEntries == NULL)
        {
            DEBUG0(sprintf(str_buf, "RSFW: Hmmm... lpCompletionPortEntries==NULL\n"));
            return rv;
        }
        for (unsigned int i = 0; i < *ulNumEntriesRemoved; i++)
        {
            if (otoaa.find(lpCompletionPortEntries[i].lpOverlapped) != otoaa.end())
            {
                if (otos.find(lpCompletionPortEntries[i].lpOverlapped) == otos.end())
                {
                    DEBUG30(sprintf(str_buf, "RSFW: WARNING: overlapped found in otoaa, BUT NOT in otos!\n"));
                }
                SOCKET s = otos[lpCompletionPortEntries[i].lpOverlapped];
                if (stoad.find(s) == stoad.end())
                {
                    if (lpCompletionPortEntries[i].dwNumberOfBytesTransferred == 0)
                    {
                        sockaddr_any* me = NULL;
                        sockaddr_any* peer = NULL;
                        int size_me = 0, size_peer = 0;
                        AcceptArgs& aa = otoaa[lpCompletionPortEntries[i].lpOverlapped];
                        DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": About to call GetAcceptExSockaddrs()\n", s));
                        GetAcceptExSockaddrs_ptr(aa.m_lpOutputBuffer, aa.m_dwReceiveDataLength, aa.m_dwLocalAddressLength, aa.m_dwRemoteAddressLength, (sockaddr**)&me, &size_me, (sockaddr**)&peer, &size_peer);
                        DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned %p (%d) %p (%d)\n", s, me, size_me, peer, size_peer));
                        if (me && peer)
                        {
                            DEBUG30(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned non NULL pointers - this is good\n", s));
                        }
                        else
                        {
                            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": GetAcceptExSockaddrs returned NULL pointer(s) %p, %p - this is BAD\n", s, me, peer));
                        }
                        char from[100], to[100];
                        peer->to_str(from);
                        me->to_str(to);
                        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Connection Established: %s -> %s\n", s, from, to));
                        //stoad.insert(pair<SOCKET, SockDesc>(s, SockDesc(s, me, peer)));
                        stoad[s] = SAL::gen_f(s, me, peer);
                    }
                    else
                    {
                        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": WTF?! getting data for the socket, the socket is not yet open\n", s));
                    }
                    //otoaa.erase(lpCompletionPortEntries[i].lpOverlapped);
                }
                else
                {
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": WTF?! AcceptEx returned, but the socket is already open\n", s));
                }
                otos.erase(lpCompletionPortEntries[i].lpOverlapped);
            }
        }
    }
    DEBUG30(sprintf(str_buf, "Returning from GetQueuedCompletionStatusEx_hook\n"));
    return rv;
}

static bool init()
{
    printf("In SAL's init!\n");

    if (access(LOGFILE, 0) == -1)  // File does not exist
    {
        //int old = umask(0);
        creat(LOGFILE, _S_IWRITE);
        //umask(old);
    }

    DEBUG0(sprintf(str_buf, "\n\nStarting...\n"));
    funchook_t* funchook = funchook_create();
    int rv;

    GUID GuidAcceptEx = WSAID_ACCEPTEX;
    DWORD dwBytes = 0;
    SOCKET dummy_socket = socket(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP);

    int iResult = WSAIoctl(dummy_socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &GuidAcceptEx, sizeof(GuidAcceptEx),
        &AcceptEx_ptr, sizeof(AcceptEx_ptr),
        &dwBytes, NULL, NULL);
    if (iResult == SOCKET_ERROR)
    {
        DEBUG0(sprintf(str_buf, "WSAIoctl failed with error: %u\n", WSAGetLastError()));
        exit(0);
    }
    //sprintf(str_buf,"WSAIoctl for AcceptEx returned %p\n", AcceptEx_ptr);
    rv = funchook_prepare(funchook, (void**)&AcceptEx_ptr, AcceptEx_hook);
    if (rv != 0) {
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    GUID GuidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
    iResult = WSAIoctl(dummy_socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &GuidGetAcceptExSockaddrs, sizeof(GuidGetAcceptExSockaddrs),
        &GetAcceptExSockaddrs_ptr, sizeof(GetAcceptExSockaddrs_ptr),
        &dwBytes, NULL, NULL);
    if (iResult == SOCKET_ERROR)
    {
        DEBUG0(sprintf(str_buf, "WSAIoctl failed with error: %u\n", WSAGetLastError()));
        exit(0);
    }

    /* Prepare hooking.
        * The return value is used to call the original send function
        * in send_hook.
        */
    WSAAccept_ptr = WSAAccept;
    rv = funchook_prepare(funchook, (void**)&WSAAccept_ptr, WSAAccept_hook);
    if (rv != 0) {
        /* error */
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }


    accept_ptr = accept;
    rv = funchook_prepare(funchook, (void**)&accept_ptr, accept_hook);
    if (rv != 0) {
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    WSARecv_ptr = WSARecv;
    rv = funchook_prepare(funchook, (void**)&WSARecv_ptr, WSARecv_hook);
    if (rv != 0) {
        /* error */
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    closesocket_ptr = closesocket;
    rv = funchook_prepare(funchook, (void**)&closesocket_ptr, closesocket_hook);
    if (rv != 0) {
        /* error */
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    WSAGetOverlappedResult_ptr = WSAGetOverlappedResult;
    rv = funchook_prepare(funchook, (void**)&WSAGetOverlappedResult_ptr, WSAGetOverlappedResult_hook);
    if (rv != 0) {
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    GetOverlappedResult_ptr = GetOverlappedResult;
    rv = funchook_prepare(funchook, (void**)&GetOverlappedResult_ptr, GetOverlappedResult_hook);
    if (rv != 0) {
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    GetQueuedCompletionStatusEx_ptr = GetQueuedCompletionStatusEx;
    rv = funchook_prepare(funchook, (void**)&GetQueuedCompletionStatusEx_ptr, GetQueuedCompletionStatusEx_hook);
    if (rv != 0) {
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    GetQueuedCompletionStatus_ptr = GetQueuedCompletionStatus;
    rv = funchook_prepare(funchook, (void**)&GetQueuedCompletionStatus_ptr, GetQueuedCompletionStatus_hook);
    if (rv != 0) {
        //MessageBoxA(NULL, "ERROR in funchook_prepare", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_prepare\n"));
        exit(0);
    }

    /* Install hooks.
        * The first 5-byte code of send() and recv() are changed respectively.
        */
    rv = funchook_install(funchook, 0);
    if (rv != 0) {
        /* error */
        //MessageBoxA(NULL, "ERROR in funchook_install", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "ERROR in funchook_install\n"));
        exit(0);
    }

    return 0;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL,
    DWORD     fdwReason,
    LPVOID    lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        /* Init Code here */
        //MessageBoxA(NULL, "Hello from Hooker", "Hooker Message", MB_OK);
        //DEBUG0(sprintf(str_buf, "INFO: Hooker starting\n"));
        init();

        //MessageBoxA(NULL, "DONE INSTALLING HOOKS", "Hooker Message", MB_OK);
        DEBUG0(sprintf(str_buf, "INFO: Hooker, done installing hooks\n"));

        break;

    case DLL_THREAD_ATTACH:
        /* Thread-specific init code here */
        break;

    case DLL_THREAD_DETACH:
        /* Thread-specific cleanup code here.
        */
        break;

    case DLL_PROCESS_DETACH:
        /* Cleanup code here */
        break;
    }
    /* The return value is used for successful DLL_PROCESS_ATTACH */
    return TRUE;
}
