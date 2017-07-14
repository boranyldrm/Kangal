//
// Created by Boran Yildirim on 13/07/2017.
//

#ifndef VLAN_HOPPING_IP_HEADERS_H
#define VLAN_HOPPING_IP_HEADERS_H

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ethernet_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
} __attribute__((__packed__));

/* IP header */
struct ip_header {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst;  /* source and dest address */
} __attribute__((__packed__));
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
} __attribute__((__packed__));


struct vlan_tag_header {
    u_short	tpid;	/*Tag protocol identifier*/
    u_short     pcp_vid;
} __attribute__((__packed__));


/* Ethernet header */
struct vlan_ethernet_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
#ifndef DISABLE_VLAN
    struct 	vlan_tag_header customer;
    struct 	vlan_tag_header service;
#endif
    u_short ether_type;                     /* IP? ARP? RARP? etc */
} __attribute__((__packed__));


/* ICMP header */
struct icmp_header {
    u_char  icmph_type;
    u_char  icmph_code;
    u_short icmph_chksum;
    /* The following data structures are ICMP type specific */
    u_short icmph_ident;
    u_short icmph_seqnum;
} __attribute__((__packed__)); /* total ICMP header length: 8 bytes (= 64 bits) */

#endif //VLAN_HOPPING_IP_HEADERS_H
