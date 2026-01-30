/* ftraceroute.c: ftraceroute
 *
 * Copyright (C) 2026 German-Service-Network <https://www.gsnw.de>
 * All Rights Reserved.
 *
 * Licensed under GNU General Public License v3
 *   (see COPYING for full license text)
 */

#if !defined(_GNU_SOURCE)
  #define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftraceroute.h"
#include "options.h"

double version = 0.2;

int main(int argc, char **argv) {

  int opt;
  int max_hops = DEFAULT_MAX_HOPS;
  int probes = DEFAULT_PROBES;
  int timeout_ms = DEFAULT_TIMEOUT_MS;

  while ((opt = getopt(argc, argv, "hvm:c:t:")) != -1) {
    switch (opt) {
      case 'h':
        usage(argv[0]);
        return 0;
      case 'v':
        printf("Version: %f\n", version);
        return 0;
      case 'm':
        max_hops = atoi(optarg);
        break;
      case 'c':
        probes = atoi(optarg);
      break;
      case 't':
        timeout_ms = atoi(optarg);
        break;
      case '?':
        if(optopt == 'm' || optopt == 'c') {
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        } else {
          fprintf(stderr, "Unknown option '-%c'\n", optopt);
        }
        usage(argv[0]);
        return -1;
      default:
        usage(argv[0]);
        return -1;
    }
  }

  // Check if at least one host is provided
  if (optind >= argc) {
    fprintf(stderr, "Error: At least one <host> is required\n");
    usage(argv[0]);
    return 1;
  }

#if defined(DEBUG) || defined(_DEBUG)
  printf("Max hops: %d\n", max_hops);
  printf("Probes: %d\n", probes);
  printf("Timeout: %d ms\n", timeout_ms);
  printf("--------------\n");
#endif /* DEBUG || _DEBUG */

  if (max_hops <= 0) max_hops = DEFAULT_MAX_HOPS;
  if (probes   <= 0) probes   = DEFAULT_PROBES;

  int num_hosts = argc - optind;
  trace_session_t *sessions = calloc(num_hosts, sizeof(trace_session_t));

  // Initialization of all sessions
  for (int i = 0; i < num_hosts; i++) {
    session_init(&sessions[i], argv[optind + i], max_hops, probes, timeout_ms, i);
  }

  // Main loop (event loop)
  while (1) {
    int active_count = 0;
    int max_fd = -1;
    fd_set readfds;
    FD_ZERO(&readfds);

    // 1. Collect FDs for select
    for (int i = 0; i < num_hosts; i++) {
      trace_session_t *s = &sessions[i];
      if (s->state == STATE_FINISHED || s->state == STATE_ERROR) continue;
      active_count++;

      // While waiting for a response, we add the socket to the read set.
      if (s->state == STATE_AWAIT_REPLY && s->sock >= 0) {
        FD_SET(s->sock, &readfds);
        if (s->sock > max_fd) max_fd = s->sock;
      }
    }
    if (active_count == 0) break; // Alles erledigt

    // 2. Select with a short timeout (10 ms) so that we can check send/timeouts.
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    select(max_fd + 1, &readfds, NULL, NULL, &tv);

    // 3. Processing for all sessions
    for (int i = 0; i < num_hosts; i++) {
      trace_session_t *s = &sessions[i];
      if (s->state == STATE_FINISHED || s->state == STATE_ERROR) continue;

      // A) Read (if data is available)
      if (s->state == STATE_AWAIT_REPLY && s->sock >= 0 && FD_ISSET(s->sock, &readfds)) {
        process_read(s);
      }

      // B) Timeout check (if still waiting)
      if (s->state == STATE_AWAIT_REPLY) {
        process_timeout_check(s);
      }

      // C) Preparing a new hop
      if (s->state == STATE_PREPARE_HOP) {
        s->current_ttl++;
        if (s->current_ttl > s->max_hops) {
          fprintf(stderr, "[%s] Target not reached (max_hops=%d).\n", s->host_arg, s->max_hops);
          s->state = STATE_FINISHED;
          session_close(s);
        } else {
          // Initialize output buffer
          s->line_off = 0;
          s->line_off += snprintf(s->line_buf + s->line_off, sizeof(s->line_buf) - s->line_off, "[%s] %2d  ", s->host_arg, s->current_ttl);

          // Set socket TTL
          if (s->dst.ss_family == AF_INET) {
            setsockopt(s->sock, IPPROTO_IP, IP_TTL, &s->current_ttl, sizeof(s->current_ttl));
          } else {
            setsockopt(s->sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &s->current_ttl, sizeof(s->current_ttl));
          }
          
          s->current_probe = 0;
          s->printed_addr = false;
          s->state = STATE_SEND_PROBE;
        }
      }

      // D) Send (when ready)
      if (s->state == STATE_SEND_PROBE) {
        process_send(s);
      }
    }
  }

  free(sessions);
  return 0;
}


/*
 * Functions
 */

void session_init(trace_session_t *s, char *host, int mh, int pp, int tm, int idx) {
  s->host_arg = host;
  s->max_hops = mh;
  s->probes_per_hop = pp;
  s->timeout_ms = tm;
  s->current_ttl = 0;
  s->reached_dest = false;
  s->ident = (getpid() & 0xFFFF) + idx; // Unique ID per session
  s->seq_base = 0;

  if (resolve_host(host, &s->dst) < 0) {
    fprintf(stderr, "[%s] Could not resolve host.\n", host);
    s->state = STATE_ERROR;
    s->sock = -1;
    return;
  }

  s->dst_len = (s->dst.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
  s->proto = (s->dst.ss_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;


  char dst_ip[INET6_ADDRSTRLEN];
  getnameinfo((struct sockaddr *)&s->dst, s->dst_len, NULL, 0, dst_ip, sizeof(dst_ip), NI_NUMERICHOST);
  printf("[%s] Start traceroute to %s (%s)\n", host, host, dst_ip);

  
 
  s->sock = socket(s->dst.ss_family, SOCK_RAW, s->proto);
  if (s->sock < 0) {
    perror("socket");
    s->state = STATE_ERROR;
    return;
  }

  // IMPORTANT: Non-blocking for single-threaded event loop
  int flags = fcntl(s->sock, F_GETFL, 0);
  fcntl(s->sock, F_SETFL, flags | O_NONBLOCK);

  s->state = STATE_PREPARE_HOP;
}

void session_close(trace_session_t *s) {
  if (s->sock >= 0) {
    close(s->sock);
    s->sock = -1;
  }
}

void process_send(trace_session_t *s) {
  if (s->current_probe >= s->probes_per_hop) {
    flush_line(s);
    if (s->reached_dest) {
      s->state = STATE_FINISHED;
      session_close(s);
    } else {
      s->state = STATE_PREPARE_HOP;
    }
    return;
  }

  unsigned char packet[PACKET_SIZE];
  memset(packet, 0, sizeof(packet));
  size_t pkt_len = 0;
  struct timeval *stamp_ptr = NULL;

  if (s->dst.ss_family == AF_INET) {
    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(s->ident);
    icmp->un.echo.sequence = htons(s->seq_base++);
        
    stamp_ptr = (struct timeval *)(packet + sizeof(struct icmphdr));
    pkt_len = sizeof(struct icmphdr) + sizeof(struct timeval);
    gettimeofday(stamp_ptr, NULL);
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, (int)pkt_len);
  } else {
    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet;
    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id = htons(s->ident);
    icmp6->icmp6_seq = htons(s->seq_base++);

    stamp_ptr = (struct timeval *)(packet + sizeof(struct icmp6_hdr));
    pkt_len = sizeof(struct icmp6_hdr) + sizeof(struct timeval);
    gettimeofday(stamp_ptr, NULL);
  }

  gettimeofday(&s->t_send, NULL);
  if (sendto(s->sock, packet, pkt_len, 0, (struct sockaddr *)&s->dst, s->dst_len) < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      s->line_off += snprintf(s->line_buf + s->line_off, sizeof(s->line_buf) - s->line_off, "* ");
      s->current_probe++;
      return;
    }
  }
  s->state = STATE_AWAIT_REPLY;
}

void process_timeout_check(trace_session_t *s) {
  struct timeval now;
  gettimeofday(&now, NULL);
  double elapsed = ms_between(s->t_send, now);
  if (elapsed > s->timeout_ms) {
    s->line_off += snprintf(s->line_buf + s->line_off, sizeof(s->line_buf) - s->line_off, "* ");
    s->current_probe++;
    s->state = STATE_SEND_PROBE;
  }
}

void process_read(trace_session_t *s) {
  unsigned char recvbuf[PACKET_SIZE];
  struct sockaddr_storage reply_addr;
  socklen_t rlen = sizeof(reply_addr);
  struct timeval t_rcv;

  ssize_t n = recvfrom(s->sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&reply_addr, &rlen);
  if (n < 0) return;

  gettimeofday(&t_rcv, NULL);
  bool match = false;
  bool is_final = false;

  if (s->dst.ss_family == AF_INET) {
    struct iphdr *ip = (struct iphdr *)recvbuf;
    int iphdrlen = ip->ihl * 4;
    if (n >= iphdrlen + 8) {
      struct icmphdr *icmph = (struct icmphdr *)(recvbuf + iphdrlen);
      if (icmph->type == ICMP_ECHOREPLY) {
        if (ntohs(icmph->un.echo.id) == s->ident && ntohs(icmph->un.echo.sequence) == (unsigned short)(s->seq_base - 1)) {
          match = true; is_final = true;
        }

      } else if (icmph->type == ICMP_TIME_EXCEEDED) {
        unsigned char *inner = (unsigned char *)icmph + 8;
        struct iphdr *ip2 = (struct iphdr *)inner;
        int ip2len = ip2->ihl * 4;
        if (n >= iphdrlen + 8 + ip2len + 8) {
          struct icmphdr *icmp2 = (struct icmphdr *)(inner + ip2len);
          if (ntohs(icmp2->un.echo.id) == s->ident && ntohs(icmp2->un.echo.sequence) == (unsigned short)(s->seq_base - 1)) {
            match = true;
          }
        }
      }
    }
  } else {
    // IPv6
    if (n >= (ssize_t)sizeof(struct icmp6_hdr)) {
      struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)recvbuf;
      if (icmp6h->icmp6_type == ICMP6_ECHO_REPLY) {
        if (ntohs(icmp6h->icmp6_id) == s->ident && ntohs(icmp6h->icmp6_seq) == (unsigned short)(s->seq_base - 1)) {
          match = true;
          is_final = true;
        }
      } else if (icmp6h->icmp6_type == ICMP6_TIME_EXCEEDED) {
        size_t offset = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr);
        if (n >= (ssize_t)(offset + sizeof(struct icmp6_hdr))) {
          struct icmp6_hdr *inner = (struct icmp6_hdr *)(recvbuf + offset);
          if (ntohs(inner->icmp6_id) == s->ident && ntohs(inner->icmp6_seq) == (unsigned short)(s->seq_base - 1)) {
            match = true;
          }
        }
      }
    }
  }

  if (match) {
    // Address buffering (once per hop)
    if (!s->printed_addr) {
      char host_name[NI_MAXHOST] = {0};
      char ip_txt[INET6_ADDRSTRLEN] = {0};
      addr_to_host((struct sockaddr *)&reply_addr, rlen, host_name, sizeof(host_name), ip_txt, sizeof(ip_txt));

      if (host_name[0] == '\0') {
        s->line_off += snprintf(s->line_buf + s->line_off, sizeof(s->line_buf) - s->line_off, "%s  ", ip_txt);
      } else {
        s->line_off += snprintf(s->line_buf + s->line_off, sizeof(s->line_buf) - s->line_off, "%s (%s)  ", host_name, ip_txt);
      }
      s->printed_addr = true;
    }
    
    double rtt = ms_between(s->t_send, t_rcv);
    s->line_off += snprintf(s->line_buf + s->line_off, sizeof(s->line_buf) - s->line_off, "%.3f ms  ", rtt);

    if (is_final) s->reached_dest = true;
    
    // Test successful -> Next test
    s->current_probe++;
    s->state = STATE_SEND_PROBE;
  }
}

void flush_line(trace_session_t *s) {
  printf("%s\n", s->line_buf);
}

unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }
  if (len == 1) {
    unsigned short tmp = 0;
    *(unsigned char *)(&tmp) = *(unsigned char *)buf;
    sum += tmp;
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

double ms_between(struct timeval a, struct timeval b) {
  // returns milliseconds between a (send) and b (recv)
  double sec = (double)(b.tv_sec - a.tv_sec);
  double usec = (double)(b.tv_usec - a.tv_usec);
  return sec * 1000.0 + usec / 1000.0;
}

int resolve_host(const char *host, struct sockaddr_storage *out) {
  memset(out, 0, sizeof(*out));
  struct addrinfo hints = {0}, *res = NULL;
  
  // AF_UNSPEC allows IPv4 AND IPv6
  hints.ai_family = AF_UNSPEC; 
  hints.ai_socktype = SOCK_RAW;
  // Leave protocol at 0 so that getaddrinfo finds the right one.
  // (or explicitly handle IPPROTO_ICMP / V6, but 0 is safer for dual stack)
  hints.ai_protocol = 0; 

  int rc = getaddrinfo(host, NULL, &hints, &res);
  if (rc != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
    return -1;
  }
  
  // Simply take the first result.
  if (res->ai_family == AF_INET) {
    memcpy(out, res->ai_addr, sizeof(struct sockaddr_in));
  } else if (res->ai_family == AF_INET6) {
    memcpy(out, res->ai_addr, sizeof(struct sockaddr_in6));
  } else {
    fprintf(stderr, "Unknown address family\n");
    freeaddrinfo(res);
    return -1;
  }

  freeaddrinfo(res);
  return 0;
}

void addr_to_host(const struct sockaddr *addr, socklen_t len, char *host, size_t hostlen, char *ip, size_t iplen) {
  // getnameinfo is already IP-agnostic as long as we pass struct sockaddr
  getnameinfo(addr, len, host, (socklen_t)hostlen, NULL, 0, NI_NAMEREQD);
  
  // inet_ntop is family-specific, getnameinfo with NI_NUMERICHOST is more universal.
  getnameinfo(addr, len, ip, (socklen_t)iplen, NULL, 0, NI_NUMERICHOST);
}

void usage(const char *progname) {
  printf("Usage: %s [options] <host> [host2 ...]\n", progname);
  printf("Options:\n");
  printf("  -h          Show this help message\n");
  printf("  -v          Show version info\n");
  printf("  -m <value>  Set max hops\n");
  printf("  -c <value>  Set probe count\n");
  printf("  -t <value>  Set timeout in ms\n");
}