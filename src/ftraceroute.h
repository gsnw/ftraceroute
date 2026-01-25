/* ftraceroute.h
 *
 * Copyright (C) 2026 German-Service-Network <https://www.gsnw.de>
 * All Rights Reserved.
 *
 * Licensed under GNU General Public License v3
 *   (see COPYING for full license text)
 */

#ifndef _FTRACEROUTE_H
#define _FTRACEROUTE_H

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

unsigned short checksum(void *b, int len);
double ms_between(struct timeval a, struct timeval b);
int resolve_host(const char *host, struct sockaddr_storage *out);
void addr_to_host(const struct sockaddr *addr, socklen_t len, char *host, size_t hostlen, char *ip, size_t iplen);
void usage(const char *progname);

#endif