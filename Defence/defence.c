#define APP_NAME		"TCP Syn Flood Defence"
#define APP_DESC		"Read the TCP Syn and IPs"
#define APP_COPYRIGHT	"No Copyright"
#define APP_DISCLAIMER	"GoodBye Attackers"

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

/* WARNING you can uncomment the printf functions for debug purpose
	in the real time not uncomment them because when printing the system can miss some packets*/



/*ip container structure definition*/
struct IP_entry ** ip_list;

/* table ronud for counting 1 minute for flushing the TCPIP_REJECTED chain*/
static time_t table_round;


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_app_banner(void);

void print_app_usage(void);

/*
 * app name/banner
 */
void print_app_banner(void) {

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

	return;
}

/*
 * print help text
 */
void print_app_usage(void) {

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

	return;
}


/*
 * callback function for pcap_loop
 * captures the TCP/IP packets 
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	static int count = 1;                   /* packet counter */

	/* get the time of first packet */
	if (count == 1) {
		time(&table_round);
	}

	// boolean value for start dropping (0 not drop, 1 drop)
	static char ip_can_drop = 0;
	
	/* declare pointers to packet headers */
	const struct ethernet_header *ethernet;  /* The ethernet header [1] */
	const struct ip_header *ip;              /* The IP header */
	const struct tcp_header *tcp;            /* The TCP header */

	int size_ip;
	int size_tcp;

	/* if 1 minutes pass from (current packet time - first packet time) and ip_can_drop == 0 
		flush the TCPIP_REJECTED and set ip_can_drop 1*/
	if ( (header->ts.tv_sec - table_round) >= 60 && !ip_can_drop ) {
		system("iptables -F TCPIP_REJECTED");
		ip_can_drop = 1;
	}
	
	/* define ethernet header */
	ethernet = (struct ethernet_header*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct ip_header*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* Altough filter just bring TCP check one more time for TCP */
	if (ip->ip_p != IPPROTO_TCP)	
		return;

	/*get the last octet of the host ip with token*/
	char ipsrc_tmp[16];
	strcpy(ipsrc_tmp, inet_ntoa(ip->ip_src));
	char* token = strtok(ipsrc_tmp, ".");
	u_char c = 0;
	while (token) {
		/* if last octet is reached*/
		if (c == 3) {
			/* index of entry array is host IP number (hash with host IP)*/
			u_char index = atoi(token);
	
			ip_update (ip_list, index, inet_ntoa(ip->ip_src), header->ts.tv_sec, header->ts.tv_usec, ip_can_drop);
		}
		token = strtok(NULL, ".");
    	c++;
	}
	
	//printf("   Protocol: TCP\n");

	//printf("\nPacket number %d:\n", count);
	count++;

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* define/compute tcp header offset */
	tcp = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	//printf("   Src port: %d\n", ntohs(tcp->th_sport));
	//printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	//printf("   TCP Flag: %d\n", ntohs(tcp->th_flags));
	//printf("   sequence: %d\n", ntohs(tcp->th_seq));
	//printf("   ack no: %d\n", ntohs(tcp->th_ack));

	return;
}

int main(int argc, char **argv) {

	/* flush the INPUT chain to prevent duplicate entries*/
	system("iptables -F INPUT");

	/* enable ssh port so if your IP is blocked from connection you can still connect to server with ssh*/
	system("iptables -I INPUT -p tcp --dport 22 -j ACCEPT");

	/*new chains for reject and drop*/
	system("iptables -N TCPIP_REJECTED");
	system("iptables -N TCPIP_DROPPED");

	/* adding subchains to INPUT chain*/
	system("iptables -A INPUT -j TCPIP_REJECTED");
	system("iptables -A INPUT -j TCPIP_DROPPED");
	
	/* flush chains*/
	system("iptables -F TCPIP_REJECTED");
	system("iptables -F TCPIP_DROPPED");



	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "dst host 10.20.40.31 and port 8080 and ip and (tcp[tcpflags] & (tcp-syn) != 0)";		/* filter expression for pcap compile */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 0;			/* number of packets to capture */

	ip_list = ip_init();	/* ip list initialization*/

	print_app_banner();


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
	printf("Number of packets: %d\n", num_packets);
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
	ip_free(ip_list);

	printf("\nCapture complete.\n");

	return 0;
}

