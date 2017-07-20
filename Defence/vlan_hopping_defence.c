#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "ip_headers.h"
#include "ip_container.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	/* declare pointers to packet headers */
	const struct vlan_ethernet_header *ethernet;  /* The ethernet header [1] */
	const struct ip_header *ip;              /* The IP header */
	const struct icmp_header *icmp;          /* The ICMP header */

	/* define ethernet header */
	ethernet = (struct vlan_ethernet_header*)(packet);
	ip = (struct ip_header*)(packet + sizeof(ethernet));
	if(sizeof(ethernet)!=SIZE_ETHERNET){
		char iptables_systemcall[90] = "iptables -t filter -A INPUT -p icmp -s ";
		strcat(iptables_systemcall, inet_ntoa(ip->ip_src));
		strcat(iptables_systemcall, " -j DROP ");

		system(iptables_systemcall);
		printf("Vlan tagged packet is dropped.\n");
	}

	return;
}

int main(int argc, char **argv) {
	int num_packets = 0;		/* number of packets to capture */

	system("iptables -F INPUT");

	char *dev = NULL;		/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
	pcap_t *handle;			/* packet capture handle */

	char filter_exp[] = "dst host 10.20.40.31 and ip and icmp";	/* filter expression for pcap compile */

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	/* find a capture device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
									
	return 0;
}
