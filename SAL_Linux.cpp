#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include "funchook.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <dlfcn.h>
#include <map>
#include <sys/stat.h>

#include "SAL.h"
#include "debug.h"
#include <time.h>

static std::map<socket_t,AbstractSocket*> stoad;
//SAL::generator SAL::gen_f=NULL;

// Squid
typedef int (*close_ptr_t)(int fd);
static close_ptr_t close_ptr=close;
static int close_hook(int fd)
{
	int save_errno=errno;
	struct stat statbuf;
	int fsrc=fstat(fd, &statbuf);
	errno=save_errno;
	int rc=close_ptr(fd);
	save_errno=errno;
	if ((rc==0) && S_ISSOCK(statbuf.st_mode))
	{
		REPORT_HOOK("close");
		DEBUG10(sprintf(str_buf,"SAL: close(%d)=%d\n",fd, rc));
		if (stoad.find(fd)!=stoad.end())
		{
			delete stoad[fd];
			stoad.erase(fd);
		}
	}
	else
	{
		//printf("Closing non-socket fd %d\n",fd);
	}
	errno=save_errno;
	return rc;
}


// nginx, tomcat
typedef int (*shutdown_ptr_t)(int sockfd, int how);
static shutdown_ptr_t shutdown_ptr=shutdown;
static int shutdown_hook(int sockfd, int how)
{
	int rc=shutdown_ptr(sockfd,how);
	int save_errno=errno;
	REPORT_HOOK("shutdown");
	if (stoad.find(sockfd)!=stoad.end())
	{
		DEBUG10(sprintf(str_buf,"SAL: shutdown(%d,%d)\n",sockfd,how));
		delete stoad[sockfd];
		stoad.erase(sockfd);
	}
	errno=save_errno;
	return rc;
}


// Squid (+varnish?), tomcat
typedef int (*accept_ptr_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static accept_ptr_t accept_ptr=accept;
static int accept_hook(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int rc=accept_ptr(sockfd, addr, addrlen);
	int save_errno=errno;
	REPORT_HOOK("accept");
	if (rc>0)
	{
		char addr_str[100];
		((sockaddr_any*)addr)->to_str(addr_str);
		DEBUG10(sprintf(str_buf,"SAL: accept(%d,%p,%p)=%d (peer is %s)\n",sockfd, addr, addrlen, rc, addr_str));
		sockaddr_any me;
		socklen_t len=sizeof(me);
		getsockname(rc,(sockaddr*)&me,&len);
		stoad[rc]=SAL::gen_f(rc,&me,((sockaddr_any*)addr));
	}
	errno=save_errno;
	return rc;
}

// nginx
typedef int (*accept4_ptr_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
static accept4_ptr_t accept4_ptr=accept4;
static int accept4_hook(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc=accept4_ptr(sockfd, addr, addrlen, flags);
	int save_errno=errno;
	REPORT_HOOK("accept4");
	if (rc>0)
	{
		char addr_str[100];
		sockaddr_any* ppeer=(sockaddr_any*)addr;
		sockaddr_any peer;
		if (addr==NULL)
		{
			socklen_t len=sizeof(peer);
			getpeername(rc,(sockaddr*)&peer,&len);
			ppeer=&peer;
		}
		ppeer->to_str(addr_str);
		DEBUG10(sprintf(str_buf,"SAL: accept4(%d,%p,%p,0x%x)=%d (peer is %s)\n",sockfd, addr, addrlen, flags,rc, addr_str));
		sockaddr_any me;
		socklen_t len=sizeof(me);
		getsockname(rc,(sockaddr*)&me,&len);
		stoad[rc]=SAL::gen_f(rc,&me,((sockaddr_any*)addr));
	}
	errno=save_errno;
	return rc;
}

// node.js
static accept4_ptr_t uv__accept4_ptr=NULL;
static int uv__accept4_hook(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int rc=uv__accept4_ptr(sockfd, addr, addrlen, flags);
	int save_errno=errno;
	REPORT_HOOK("uv__accept4");
	if (rc>0)
	{
		char addr_str[100];
		sockaddr_any* ppeer=(sockaddr_any*)addr;
		sockaddr_any peer;
		if (addr==NULL)
		{
			socklen_t len=sizeof(peer);
			getpeername(rc,(sockaddr*)&peer,&len);
			ppeer=&peer;
		}
		ppeer->to_str(addr_str);
		DEBUG10(sprintf(str_buf,"SAL: uv__accept4(%d,%p,%p,0x%x)=%d (peer is %s)\n",sockfd, addr, addrlen, flags,rc, addr_str));
		sockaddr_any me;
		socklen_t len=sizeof(me);
		getsockname(rc,(sockaddr*)&me,&len);
		stoad[rc]=SAL::gen_f(rc,&me,ppeer);
	}
	errno=save_errno;
	return rc;
}

// nginx, tomcat
typedef ssize_t (*recv_ptr_t)(int sockfd, void *buf, size_t len, int flags);
static recv_ptr_t recv_ptr=recv;
static ssize_t recv_hook(int sockfd, void *buf, size_t len, int flags)
{
	ssize_t rc=recv_ptr(sockfd, buf, len, flags);
	int save_errno=errno;
	REPORT_HOOK("recv");
	DEBUG20(sprintf(str_buf,"SAL: recv(%u, %p, %lu, %u)=%ld\n",sockfd, buf, len, flags, rc));
	if (rc>0)
	if (stoad.find(sockfd)!=stoad.end())
	{
		if (rc>0)
		{
			bool ok=stoad[sockfd]->onRead((char*)buf,rc);
			if (!ok)
                	{
	        		// Using close_ptr() confuses node.js, and it crashes...
	                    shutdown_ptr(sockfd, SHUT_RDWR);
	                    //DEBUG0(sprintf(str_buf, "SAL: Socket " SOCK_FORMAT ": Erasing from stosd[] (supposedly it is closed now).\n", s));
        	            delete stoad[sockfd];
                	    stoad.erase(sockfd);
			}
                }	
		else if (rc==0)
		{
			// EOF
			DEBUG10(sprintf(str_buf,"SAL: EOF (via recv) on sockfd %d\n",sockfd));
        	  	delete stoad[sockfd];
	           	stoad.erase(sockfd);
		}	
	}
	errno=save_errno;
	return rc;
}

// node.js, Squid
typedef ssize_t (*read_ptr_t)(int fd, void *buf, size_t count);
static read_ptr_t read_ptr=read;
static ssize_t read_hook(int fd, void *buf, size_t count)
{
	ssize_t rc=read_ptr(fd, buf, count);
	int save_errno=errno;
	if (stoad.find(fd)!=stoad.end())
	{
		REPORT_HOOK("read");
		DEBUG20(sprintf(str_buf,"SAL: read(%u, %p, %lu)=%ld\n",fd, buf, count, rc));
		if (rc>0)
		{
			bool ok=stoad[fd]->onRead((char*)buf,rc);
			if (!ok)
        	       	{
	        		// Using close_ptr() confuses node.js, and it crashes...
				shutdown_ptr(fd, SHUT_RDWR);
        	  		delete stoad[fd];
	           		stoad.erase(fd);
			}
		}
		else if (rc==0)
		{
			// EOF
			DEBUG10(sprintf(str_buf,"SAL: EOF (via read) on sockfd %d\n",fd));
        	  	delete stoad[fd];
	           	stoad.erase(fd);
		}	
	}
	errno=save_errno;
	return rc;
}

// Abyss?
typedef ssize_t (*recvfrom_ptr_t)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
static recvfrom_ptr_t recvfrom_ptr=recvfrom;
static ssize_t recvfrom_hook(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	ssize_t rc=recvfrom_ptr(sockfd, buf, len, flags, src_addr, addrlen);
	int save_errno=errno;
	REPORT_HOOK("recvfrom");
	DEBUG20(sprintf(str_buf,"SAL: recvfrom(%u, %p, %lu, %u)=%lu\n",sockfd, buf, len, flags, rc));
	if (stoad.find(sockfd)!=stoad.end())
	{
		if (rc>0)
		{
			bool ok=stoad[sockfd]->onRead((char*)buf,rc);
			if (!ok)
        	      	{
		        	// Using close_ptr() confuses node.js, and it crashes...
				shutdown_ptr(sockfd, SHUT_RDWR);
        		  	delete stoad[sockfd];
	      			stoad.erase(sockfd);
			}
		}
	}
	errno=save_errno;
	return rc;
}


void __attribute__ ((constructor)) my_init(void)
{
	if( access(LOGFILE , F_OK ) == -1 )  // File does not exist
	{
		int old=umask(0);
		creat(LOGFILE, 00777);
		umask(old);
	}
		
	//DEBUG0(sprintf(str_buf,"SAL: SAL::init() started, gen=%p\n", gen));
	//gen_f=gen;
	funchook_t *funchook = funchook_create();	
	if (funchook_prepare(funchook,(void**)&close_ptr, (void*)close_hook)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in preparing for close() hooking.\n"));
		exit(0);
	}
	if (funchook_prepare(funchook,(void**)&accept_ptr, (void*)accept_hook)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in preparing for accept() hooking.\n"));
		exit(0);
	}
	if (funchook_prepare(funchook,(void**)&accept4_ptr, (void*)accept4_hook)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in preparing for accept4() hooking.\n"));
		exit(0);
	}
	if (funchook_prepare(funchook,(void**)&recv_ptr, (void*)recv_hook)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in preparing for recv() hooking.\n"));
		exit(0);
	}
	if (funchook_prepare(funchook,(void**)&recvfrom_ptr, (void*)recvfrom_hook)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in preparing for recvfrom() hooking.\n"));
		exit(0);
	}
	if (funchook_prepare(funchook,(void**)&read_ptr, (void*)read_hook)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in preparing for read() hooking.\n"));
		exit(0);
	}
	if (funchook_prepare(funchook,(void**)&shutdown_ptr, (void*)shutdown_hook)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in preparing for shutdown() hooking.\n"));
		exit(0);
	}

	// Special treatment for uv__accept4 - we don't hook it if it's not there...
	uv__accept4_ptr=(accept4_ptr_t)dlsym(RTLD_DEFAULT,"uv__accept4");
	if (uv__accept4_ptr!=NULL)
	{
		DEBUG0(sprintf(str_buf,"SAL: uv__accept4 found - hooking it.\n"));
		
		if (funchook_prepare(funchook,(void**)&uv__accept4_ptr, (void*)uv__accept4_hook)!=0)
		{
			DEBUG0(sprintf(str_buf,"SAL: Error in preparing for uv__accept4() hooking.\n"));
			exit(0);
		}
	}
	else
	{
		DEBUG0(sprintf(str_buf,"SAL: uv__accept4 not found. Moving on.\n"));
	}	
	
	if (funchook_install(funchook,0)!=0)
	{
		DEBUG0(sprintf(str_buf,"SAL: Error in funchook_install().\n"));
		exit(0);
	}

	DEBUG0(sprintf(str_buf,"SAL: SAL::init completed successfully.\n"));
	return;
}
