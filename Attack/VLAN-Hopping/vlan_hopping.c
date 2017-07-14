#include "../../Defence/ip_headers.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../includes/lib_attack.h"
#include <stdlib.h>

#define ICMP_PACKET_SIZE 64

struct icmp_packet {
    struct icmp_header icmp_hdr;
    u_char msg[ICMP_PACKET_SIZE - sizeof(struct icmp_header)];
};

int main(int argc, char const *argv[]) {
    /**************************************************************/

    FILE *file=fopen("./VLAN-Hopping/vlan_hopping_configuration.conf","r");
    char sourceIP[16];
    char sourceMAC[18];
    char sm1[4],sm2[4],sm3[4],sm4[4],sm5[4],sm6[4];
    char *sms[6]={sm1,sm2,sm3,sm4,sm5,sm6};
    char buff[50];

    for(int i=0;i<8;i++){
	fscanf(file,"%s",buff);
    }
    strcpy(sourceIP, buff);
    printf("Source IP: %s\n", sourceIP);

    for(int i=0;i<8;i++){
	fscanf(file,"%s",buff);
    }
    strcpy(sourceMAC, buff);
    printf("Source MAC: %s\n", sourceMAC);

    fclose(file);

    char *tokenPtr;
    tokenPtr=strtok(sourceMAC, ":\n");
    strcpy(sms[0], "0x");
    strcpy(sms[0], tokenPtr);

    for(int i=1;i<6;i++){
	strcpy(sms[i], "0x");
	strcat(sms[i], tokenPtr);
	tokenPtr=strtok(NULL, ":\n");
    }

/**************************************************************/

    int packet_size = sizeof(struct vlan_ethernet_header) + sizeof(struct ip_header) + sizeof(struct icmp_packet);

    u_char *packet = malloc((size_t) packet_size);


    struct vlan_ethernet_header * eth_hdr = (struct vlan_ethernet_header *) packet;
    struct ip_header * ip_hdr = (struct ip_header *) (packet + sizeof(struct vlan_ethernet_header));
    struct icmp_packet * icmp_pck = (struct icmp_packet *) (ip_hdr + sizeof(struct ip_header));

    u_char tmp_dest_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_char tmp_src_mac[ETHER_ADDR_LEN] = {0x98, 0x01, 0xa7, 0x9f, 0x05, 0x13};

    strncpy((char *)eth_hdr->ether_dhost, (const char *)tmp_dest_mac, ETHER_ADDR_LEN);
    strncpy((char *)eth_hdr->ether_shost, (const char *)tmp_src_mac, ETHER_ADDR_LEN);

    eth_hdr->customer.tpid = 0x8100;	// 802.1Q
    eth_hdr->customer.pcp_dei = 0;
    eth_hdr->customer.vid = 1;

    eth_hdr->service.tpid = 0x8100;	// 802.1Q
    eth_hdr->service.pcp_dei = 0;
    eth_hdr->service.vid = 100;

    eth_hdr->ether_type = 0x0800;	/* IP type */

    ip_hdr->ip_vhl = (u_char)0x45;  /* version 4, length 5*/
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = packet_size - sizeof(struct vlan_ethernet_header);
    ip_hdr->ip_id = htons(54321);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = 1;   /*ICMP protocol*/
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src.s_addr = inet_addr("10.20.50.222");
    ip_hdr->ip_dst.s_addr = inet_addr("255.255.255.255");

    printf("%d\n", ip_hdr->ip_len);

    ip_hdr->ip_sum = csum((unsigned short *) (packet + sizeof(struct vlan_ethernet_header)), ip_hdr->ip_len >> 1);

    icmp_pck->icmp_hdr.icmph_type = 8;   /* echo */
    icmp_pck->icmp_hdr.icmph_code = 0;
    icmp_pck->icmp_hdr.icmph_chksum = 0;
    icmp_pck->icmp_hdr.icmph_ident = 0;
    icmp_pck->icmp_hdr.icmph_seqnum = 0;
    strncpy(icmp_pck->msg, "Hello", ICMP_PACKET_SIZE - sizeof(struct icmp_header));

    icmp_pck->icmp_hdr.icmph_chksum = csum((unsigned short *) icmp_pck, sizeof(struct icmp_packet));


    printf("%d\n", ip_hdr->ip_sum);
    printf("%d\n", icmp_pck->icmp_hdr.icmph_chksum);

    return 0;
}
