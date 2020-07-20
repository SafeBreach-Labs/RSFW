#ifndef _DEBUG_H
#define _DEBUG_H
#include <cstdio>
#include <ctime>
#include <cstring>
#include "platform.h"
#include <unistd.h>
#include <fcntl.h>

#define USE_STDOUT false

#define PRINTOUT(x)                                 \
{                                                   \
    SAVE_ERROR(save_error_var);                     \
    int fh=USE_STDOUT?1:open(LOGFILE,O_WRONLY|O_APPEND);  		\
    if (fh==-1) printf("ERROR: in open, fh==-1 => errno=%d\n", errno);	\
    time_t t=time(NULL);                            \
    char tt[100];                                   \
    strcpy(tt,ctime(&t));                           \
    tt[strlen(tt)-1]='\0';                          \
    write(fh,tt,(unsigned int)strlen(tt));				\
    write(fh,": ",2);					\
    char str_buf[1000];					\
    x;                                              \
    write(fh,str_buf,(unsigned int)strlen(str_buf));			\
    if(!USE_STDOUT)                                 \
    {                                               \
        close(fh);                                 \
    }                                               \
    RESTORE_ERROR(save_error_var);                  \
}


#define DEBUG0RAW(x)                                \
{                                                   \
    SAVE_ERROR(save_error_var);                     \
    int fh=USE_STDOUT?1:open(LOGFILE,O_WRONLY|O_APPEND);  		\
    char str_buf[1000];					\
    x;                                              \
    write(fh,str_buf,(unsigned int)strlen(str_buf));			\
    if(!USE_STDOUT)                                 \
    {                                               \
        close(fh);                                 \
    }                                               \
    RESTORE_ERROR(save_error_var);                  \
}


#define DEBUG0(x) PRINTOUT(x)
#define DEBUG10(x) PRINTOUT(x)
#define DEBUG20(x) PRINTOUT(x)
//#define DEBUG30(x) PRINTOUT(x)
#define DEBUG30(x)

#define REPORT_HOOK(x) PRINTOUT(sprintf(str_buf,"SAL: IN HOOK %s\n", (x)))

#endif // _DEBUG_H