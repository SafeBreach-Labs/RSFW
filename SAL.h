#ifndef _SAL_H
#define _SAL_H

#include <map>
#include "AbstractSocket.h"
#include "sockaddr_any.h"

class SAL
{
public:
    typedef AbstractSocket* (*generator)(socket_t s, sockaddr_any* me, sockaddr_any* peer);
	static generator gen_f;
};

#endif // _SAL_H