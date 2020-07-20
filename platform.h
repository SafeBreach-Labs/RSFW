#ifndef _PLATFORM_H
#define _PLATFORM_H

#if _MSC_VER // Windows
#define _CRT_SECURE_NO_WARNINGS
#include <io.h>
#define open _open
#define write _write
#define close _close
#define access _access
#define creat _creat
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32")
typedef SOCKET socket_t;
#define MIN min
#ifdef _WIN64
#define SOCK_FORMAT "%lld"
#else
#define SOCK_FORMAT "%d"
#endif
typedef struct { int wsa_last_error; DWORD last_error; } save_error_t;
#define SAVE_ERROR(v) save_error_t v={WSAGetLastError(), GetLastError()};
#define RESTORE_ERROR(v) {WSASetLastError(v.wsa_last_error); SetLastError(v.last_error);}
#define LOGFILE "C:\\tmp\\sal.txt"
#define IPv4_ADDRESS_AS_BYTE_ARRAY(x) ((unsigned char*)&((x).S_un.S_addr))
#define IPv6_ADDRESS_AS_BYTE_ARRAY(x) ((x).u.Byte)
#define IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(x) ((x).u.Word)

#else  // Linux
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#define MIN std::min
#define SOCK_FORMAT "%d"
#define _strnicmp strncasecmp 
#define SAVE_ERROR(v) int v=errno;
#define RESTORE_ERROR(v) errno=v;
#define LOGFILE "/tmp/sal.txt"
#define IPv4_ADDRESS_AS_BYTE_ARRAY(x) ((unsigned char*)&((x).s_addr))
#define IPv6_ADDRESS_AS_BYTE_ARRAY(x) ((x).s6_addr)
#define IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(x) ((uint16_t*)((x).s6_addr))
#endif

#endif // _PLATFORM_H