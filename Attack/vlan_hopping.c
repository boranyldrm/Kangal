#include "../Defence/ip_headers.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


int main(int argc, char const *argv[]) {
    int packet_size = sizeof(struct vlan_ethernet_header) + sizeof(struct ip_header) + sizeof(struct icmp_header);

    u_char *packet = malloc((size_t) packet_size);


    struct vlan_ethernet_header * eth_hdr = (struct vlan_ethernet_header *) packet;
    struct ip_header * ip_hdr = (struct ip_header *) (packet + sizeof(struct vlan_ethernet_header));
    struct icmp_header * icmp_hdr = (struct icmp_header *) (ip_hdr + sizeof(struct ip_header));

    u_char tmp_dest_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_char tmp_src_mac[ETHER_ADDR_LEN] = {0x98, 0x01, 0xa7, 0x9f, 0x05, 0x13};

    strncpy((char *)eth_hdr->ether_dhost, (const char *)tmp_dest_mac, ETHER_ADDR_LEN);
    strncpy((char *)eth_hdr->ether_shost, (const char *)tmp_src_mac, ETHER_ADDR_LEN);

    eth_hdr->customer.tpid = 0x88A8;	// 802.1ad
    eth_hdr->customer.pcp_dei = 0;
    eth_hdr->customer.vid = 1;

    eth_hdr->service.tpid = 0x8100;	// 802.1Q
    eth_hdr->service.pcp_dei = 0;
    eth_hdr->service.vid = 100;

    eth_hdr->ether_type = 0x0800;	/* IP type */

    ip_hdr->ip_vhl = (u_char)0x45;  /* version 4, length 5*/
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(packet_size);
    ip_hdr->ip_id = htons(rand());
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = 1;   /*ICMP protocol*/
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src.s_addr = inet_addr("10.20.50.222");
    ip_hdr->ip_dst.s_addr = inet_addr("255.255.255.255");


    icmp_hdr->icmph_type = 8;   /* echo */
    icmp_hdr->icmph_code = 0;
    icmp_hdr->icmph_chksum = 0;
    icmp_hdr->icmph_ident = 0;
    icmp_hdr->icmph_seqnum = 0;


    return 0;
}
