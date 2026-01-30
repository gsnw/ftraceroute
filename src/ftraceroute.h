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
#include <sys/select.h>
#include <netinet/in.h>

/* State definition for a session */
typedef enum {
  STATE_PREPARE_HOP,  // Ready for next hop (increase TTL, initialize buffer)
  STATE_SEND_PROBE,   // Ready to send a sample
  STATE_AWAIT_REPLY,  // Waiting for response (select)
  STATE_FINISHED,     // Goal achieved or Max Hops through
  STATE_ERROR         // Error case (socket defective, etc.)
} session_state_t;

/* Structure that holds the state of a single trace operation */
typedef struct {
    char *host_arg;               // Hostname from arguments
    struct sockaddr_storage dst;  // destination address
    socklen_t dst_len;
    int sock;                     // Socket File Descriptor
    int proto;                    // IPPROTO_ICMP or IPPROTO_ICMPV6
    uint16_t ident;               // Unique ID for ICMP
    uint16_t seq_base;            // sequence counter
    int max_hops;
    int probes_per_hop;
    int timeout_ms;
    
    // Current progress
    int current_ttl;
    int current_probe;
    bool reached_dest;
    session_state_t state;

    // Timing for current rehearsal
    struct timeval t_send;

    // Output buffering (for atomic line output)
    char line_buf[2048];
    int line_off;
    bool printed_addr;            // Has the address for this hop already been buffered?
} trace_session_t;

void session_init(trace_session_t *s, char *host, int mh, int pp, int tm, int idx);
void session_close(trace_session_t *s);
void process_send(trace_session_t *s);
void process_timeout_check(trace_session_t *s);
void process_read(trace_session_t *s);
void flush_line(trace_session_t *s);
unsigned short checksum(void *b, int len);
double ms_between(struct timeval a, struct timeval b);
int resolve_host(const char *host, struct sockaddr_storage *out);
void addr_to_host(const struct sockaddr *addr, socklen_t len, char *host, size_t hostlen, char *ip, size_t iplen);
void usage(const char *progname);

#endif