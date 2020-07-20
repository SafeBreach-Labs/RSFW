#ifndef _ABSTRACTSOCKET_H
#define _ABSTRACTSOCKET_H

#include "platform.h" // for socket_t
#include <stdint.h>
#include "sockaddr_any.h"

class AbstractSocket
{
protected:
    socket_t m_s;
    sockaddr_any m_me, m_peer;
public:
    //AbstractSocket() :
    //    m_s(0) {}
    AbstractSocket(socket_t s, sockaddr_any me, sockaddr_any peer) :
        m_s(s), m_me(me), m_peer(peer) {}
    virtual bool onRead(char* buf, size_t len) = 0;
    virtual ~AbstractSocket() {}
};

#endif // _ABSTRACTSOCKET_H