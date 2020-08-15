#ifndef __KTCP_DEBUG_H
#define __KTCP_DEBUG_H

int dump_connections(char __user *buff, size_t len);

#define trace_connections() dump_connections(NULL, UINT_MAX);

#endif /*__KTCP_DEBUG_H*/
