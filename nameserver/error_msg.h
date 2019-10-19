#ifndef __ERROR_MSG_H__
#define __ERRPR_MSG_H__

inline void error(const char *msg);

void error(const char *msg)
{
    perror(msg);
    exit(1);
}
#endif
