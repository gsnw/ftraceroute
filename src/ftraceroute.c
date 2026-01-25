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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftraceroute.h"
#include "options.h"

double version = 0.1;

/* Mutex for synchronized output to stdout */
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Struct to pass arguments to the thread */
typedef struct {
    char *host;
    int max_hops;
    int probes;
    int timeout_ms;
    uint16_t thread_id; /* Unique ID for ICMP correlation */
} trace_args_t;

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
  pthread_t *threads = malloc(sizeof(pthread_t) * num_hosts);
  trace_args_t *t_args = malloc(sizeof(trace_args_t) * num_hosts);

  for (int i = 0; i < num_hosts; i++) {
    t_args[i].host = argv[optind + i];
    t_args[i].max_hops = max_hops;
    t_args[i].probes = probes;
    t_args[i].timeout_ms = timeout_ms;
    // Generate a unique ID for this thread (mix PID and index) to separate ICMP replies
    t_args[i].thread_id = (getpid() & 0xFF00) | ((i + 1) & 0x00FF);

    if (pthread_create(&threads[i], NULL, run_trace, &t_args[i]) != 0) {
      perror("pthread_create");
    }
  }

  // Wait for all threads to finish
  for (int i = 0; i < num_hosts; i++) {
    pthread_join(threads[i], NULL);
  }

  free(threads);
  free(t_args);
  return 0;
}

void *run_trace(void *arg) {
  trace_args_t *args = (trace_args_t *)arg;

  // Resolve Host (IPv4 or IPv6)
  struct sockaddr_storage dst_store;
  if (resolve_host(args->host, &dst_store) < 0) return NULL;

  struct sockaddr *dst = (struct sockaddr *)&dst_store;
  socklen_t dst_len = (dst->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

  char dst_ip[INET6_ADDRSTRLEN];
  getnameinfo(dst, dst_len, NULL, 0, dst_ip, sizeof(dst_ip), NI_NUMERICHOST);

  pthread_mutex_lock(&log_mutex);
  printf("[%s] Start traceroute to %s (%s)\n", args->host, args->host, dst_ip);
  pthread_mutex_unlock(&log_mutex);

  // Choose Protocol based on family
  int proto = (dst->sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;

  int sock = socket(dst->sa_family, SOCK_RAW, proto);
  if (sock < 0) {
    // Output error protected by mutex
    pthread_mutex_lock(&log_mutex);
    fprintf(stderr, "[%s] ", args->host);
    perror("socket creation failed");
    pthread_mutex_unlock(&log_mutex);
    return NULL;
  }

  // Set recv timeout
  struct timeval tv;
  tv.tv_sec  = args->timeout_ms / 1000;
  tv.tv_usec = (args->timeout_ms % 1000) * 1000;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("setsockopt(SO_RCVTIMEO)");
  }

  // Use the unique thread_id assigned in main instead of just getpid()
  unsigned short ident = args->thread_id;
  unsigned short seq_base = 0;
  bool reached = false;

  for (int ttl = 1; ttl <= args->max_hops && !reached; ++ttl) {
    if (dst->sa_family == AF_INET) {
      if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt(IP_TTL)");
        close(sock);
        return NULL;
      }
    } else {
      if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt(IPV6_UNICAST_HOPS)");
        close(sock);
        return NULL;
      }
    }

    // Create buffer for entire line to prevent “mixed output”
    char line_buf[2048];
    size_t off = 0;
    off += snprintf(line_buf + off, sizeof(line_buf) - off, "[%s] %2d  ", args->host, ttl);

    bool printed_addr = false;

    for (int p = 0; p < args->probes; ++p) {
      unsigned char packet[PACKET_SIZE];
      memset(packet, 0, sizeof(packet));
      size_t pkt_len = 0;

      struct timeval *stamp_ptr = NULL;

      // Build Packet
      if (dst->sa_family == AF_INET) {
        struct icmphdr *icmp = (struct icmphdr *)packet;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = htons(ident);
        icmp->un.echo.sequence = htons(seq_base++);
        
        stamp_ptr = (struct timeval *)(packet + sizeof(struct icmphdr));
        pkt_len = sizeof(struct icmphdr) + sizeof(struct timeval);
        
        gettimeofday(stamp_ptr, NULL);
        icmp->checksum = 0;
        icmp->checksum = checksum(packet, (int)pkt_len);
      } else {
        // IPv6 ICMP Header construction
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_id = htons(ident);
        icmp6->icmp6_seq = htons(seq_base++);
        
        stamp_ptr = (struct timeval *)(packet + sizeof(struct icmp6_hdr));
        pkt_len = sizeof(struct icmp6_hdr) + sizeof(struct timeval);
        
        gettimeofday(stamp_ptr, NULL);
        // NOTE: Kernel calculates Checksum for ICMPv6 RAW sockets!
        icmp6->icmp6_cksum = 0;
      }

      struct timeval t_send;
      gettimeofday(&t_send, NULL);
      if (sendto(sock, packet, pkt_len, 0, dst, dst_len) < 0) {
        perror("sendto");
        if (off < sizeof(line_buf)) {
          off += snprintf(line_buf + off, sizeof(line_buf) - off, "* ");
        }
        continue;
      }

      // Receive Loop
      unsigned char recvbuf[PACKET_SIZE];
      for (;;) {
        struct sockaddr_storage reply_addr;
        socklen_t rlen = sizeof(reply_addr);
        struct timeval t_rcv;
        
        ssize_t n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&reply_addr, &rlen);
        
        if (n < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (off < sizeof(line_buf)) {
              off += snprintf(line_buf + off, sizeof(line_buf) - off, "* ");
            }
            break; 
          } else {
            perror("recvfrom");
            break;
          }
        }
        gettimeofday(&t_rcv, NULL);

        bool match = false;
        bool final_reply = false;

        // --- Parsing Response ---
        if (dst->sa_family == AF_INET) {
          // IPv4: RAW socket delivers IP header + payload
          struct iphdr *ip = (struct iphdr *)recvbuf;
          int iphdrlen = ip->ihl * 4;
          if (n < iphdrlen + 8) continue;

          struct icmphdr *icmph = (struct icmphdr *)(recvbuf + iphdrlen);

          if (icmph->type == ICMP_ECHOREPLY) {
            if (ntohs(icmph->un.echo.id) == ident && ntohs(icmph->un.echo.sequence) == (unsigned short)(seq_base - 1)) {
              match = true;
              final_reply = true;
            }
          } else if (icmph->type == ICMP_TIME_EXCEEDED) {
            // Inner IP packet
            unsigned char *inner = (unsigned char *)icmph + 8;
            struct iphdr *ip2 = (struct iphdr *)inner;
            int ip2len = ip2->ihl * 4;
            if (n >= iphdrlen + 8 + ip2len + 8) {
                struct icmphdr *icmp2 = (struct icmphdr *)(inner + ip2len);
                if (ntohs(icmp2->un.echo.id) == ident && ntohs(icmp2->un.echo.sequence) == (unsigned short)(seq_base - 1)) {
                  match = true;
                }
            }
          }
        } else {
          // IPv6: RAW socket normally delivers ONLY the ICMP header (without IPv6 header)
          // Check whether there is enough data for ICMPv6 headers
          if (n < (ssize_t)sizeof(struct icmp6_hdr)) continue;

          struct icmp6_hdr *icmp6h = (struct icmp6_hdr *)recvbuf;

          if (icmp6h->icmp6_type == ICMP6_ECHO_REPLY) {
            if (ntohs(icmp6h->icmp6_id) == ident && ntohs(icmp6h->icmp6_seq) == (unsigned short)(seq_base - 1)) {
              match = true;
              final_reply = true;
            }
          } else if (icmp6h->icmp6_type == ICMP6_TIME_EXCEEDED) {
            // Payload structure: [ICMP6 Header (8 bytes)] + [Original IPv6 Header (40 bytes)] + [Original ICMP6 Header Start]
            // Skip 8 (ICMP header) + 40 (inner IPv6 header) to get to the inner ICMP header.
            size_t offset_to_inner_icmp = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr);
            
            if (n >= (ssize_t)(offset_to_inner_icmp + sizeof(struct icmp6_hdr))) {
              struct icmp6_hdr *inner_icmp = (struct icmp6_hdr *)(recvbuf + offset_to_inner_icmp);
              if (ntohs(inner_icmp->icmp6_id) == ident && ntohs(inner_icmp->icmp6_seq) == (unsigned short)(seq_base - 1)) {
                match = true;
              }
            }
          }
        }

        if (!match) continue;

        if (!printed_addr) {
          char host_name[NI_MAXHOST] = {0};
          char ip_txt[INET6_ADDRSTRLEN] = {0};
          
          addr_to_host((struct sockaddr *)&reply_addr, rlen, host_name, sizeof(host_name), ip_txt, sizeof(ip_txt));
          
          // Write address to buffer (only for the first hit per hop)
          int written = 0;
          if (host_name[0] == '\0') {
            written = snprintf(line_buf + off, sizeof(line_buf) - off, "%s  ", ip_txt);
          } else {
            written = snprintf(line_buf + off, sizeof(line_buf) - off, "%s (%s)  ", host_name, ip_txt);
          }
          if (written > 0) off += written;
          printed_addr = true;
        }

        double rtt_ms = ms_between(t_send, t_rcv);
        if (off < sizeof(line_buf)) {
          off += snprintf(line_buf + off, sizeof(line_buf) - off, "%.3f ms  ", rtt_ms);
        }

        if (final_reply) reached = true;
        break; // Next probe
      } 
    } 

    // Now output the entire line atomically
    pthread_mutex_lock(&log_mutex);
    printf("%s\n", line_buf);
    pthread_mutex_unlock(&log_mutex);
    if (reached) break;
  }

  if (!reached) {
    fprintf(stderr, "[%s] Ziel nicht erreicht (max_hops=%d).\n", args->host, args->max_hops);
  }

  close(sock);
  return NULL;
}

/*
 * Functions
 */

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