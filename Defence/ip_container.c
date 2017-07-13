#include "ip_container.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct IP_entry** ip_init () {
	/* Entry 0 will not be used*/
	struct IP_entry ** ip_tmp = calloc(IP_ARR_SIZE + 1, sizeof(struct IP_entry));

	/* initialization of IP_entry array with default 0 values*/
	for (int i = 1; i <= IP_ARR_SIZE; ++i) {
		ip_tmp[i] = malloc(sizeof(struct IP_entry));
		ip_tmp[i]->count = 0;
		ip_tmp[i]->ts_index = 0;
		ip_tmp[i]->is_rejected = 0;
	}

	return ip_tmp;
}

void ip_update (struct IP_entry **ip_list, u_char index, char* source_ip, long int sec, long int usec, char can_drop) {
	/* increment the packet counter of specific entry*/
	ip_list[index]->count++;

	/* current index of timestamps array*/
	u_char curr_index = ip_list[index]->ts_index;

	/* current timestamp of timestamps array */
	struct IP_timestamp * curr = &(ip_list[index]->timestamps[curr_index]);
	curr->sec = sec;
	curr->usec = usec;

	/* next index timestamp of current timestamp*/
	struct IP_timestamp next = ip_list[index]->timestamps[(curr_index + 1) % 50];

	/*This checks count > 50 and time difference < 3*/
	if ((curr->sec - next.sec) < 3) {

		/* if ip address is not rejected before then reject the IP address*/
		if (ip_list[index]->is_rejected == 0) {

			/* make a system call for reject the IP address with TCP-RST*/
			char iptables_systemcall[100] = "iptables -t filter -A TCPIP_REJECTED -p tcp -s ";
			strcat(iptables_systemcall, source_ip);
			strcat(iptables_systemcall, " -j REJECT --reject-with tcp-reset");

			system(iptables_systemcall);

			/* ip address is rejected*/
			ip_list[index]->is_rejected = 1;
		}
		/* if can_drop is 1 since 60 seconds has passed and if the ip address already rejected then drop the IP address */
		else if( can_drop && ip_list[index]->is_rejected == 1 ) {

			/* make a systemcall for drop the IP address*/
			char iptables_systemcall[90] = "iptables -t filter -A TCPIP_DROPPED -p tcp -s ";
			strcat(iptables_systemcall, source_ip);
			strcat(iptables_systemcall, " -j DROP ");

			system(iptables_systemcall);

			/* ip address is dropped*/
			ip_list[index]->is_rejected = 2;
		}
	}
	
	/* increment the index and get the modulo 50 */
	(ip_list[index]->ts_index)++;
	(ip_list[index]->ts_index) %= 50;
}

/* clear the IP list */
void ip_free(struct IP_entry **ip_list) {
	if (ip_list) {
		for (int i = 0; i < IP_ARR_SIZE; ++i) {
			free(ip_list[i]);
		}
		free(ip_list);
	}
}
