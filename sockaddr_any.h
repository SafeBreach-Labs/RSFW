#ifndef _SOCKADDR_ANY_H
#define _SOCKADDR_ANY_H
#include "platform.h"
#include <cstdio>

class sockaddr_any
{
private:
    char data[sizeof(sockaddr_in6)];

public:
    void to_str(char* str)
    {
        if (((sockaddr*)data)->sa_family == AF_INET)
        {
            // IPv4
            sprintf(str, "(IPv4) %hhu.%hhu.%hhu.%hhu:%hu", 
                IPv4_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in*)data)->sin_addr)[0],
                IPv4_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in*)data)->sin_addr)[1],
                IPv4_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in*)data)->sin_addr)[2],
                IPv4_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in*)data)->sin_addr)[3],
                ntohs(((sockaddr_in*)data)->sin_port));
        }
        else if (((sockaddr*)data)->sa_family == AF_INET6)
        {
            // IPv6
            if ((ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[0]) == 0x0000) &&
                (ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[1]) == 0x0000) &&
                (ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[2]) == 0x0000) &&
                (ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[3]) == 0x0000) &&
                (ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[4]) == 0x0000) &&
                (ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[5]) == 0xFFFF))
            {
                // IPv4-in-IPv6, so we "convert" it to IPv4 (e.g. Java/Tomcat)
                sprintf(str, "(IPv4-in-IPv6) %hhu.%hhu.%hhu.%hhu:%hu",
                    IPv6_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[12],
                    IPv6_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[13],
                    IPv6_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[14],
                    IPv6_ADDRESS_AS_BYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[15],
                    ntohs(((sockaddr_in6*)data)->sin6_port));
            }
            else
            {
                // regular IPv6
                sprintf(str, "(IPv6) [%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx]:%hu",
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[0]),
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[1]),
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[2]),
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[3]),
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[4]),
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[5]),
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[6]),
                    ntohs(IPv6_ADDRESS_AS_DOUBLEBYTE_ARRAY(((sockaddr_in6*)data)->sin6_addr)[7]),
                    ntohs(((sockaddr_in6*)data)->sin6_port));
            }
        }
        return;
    }
};

#endif // _SOCKADDR_ANY_H
