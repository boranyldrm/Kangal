#include "ip_container.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct IP_entry** ip_init () {
	/* Entry 0 will not be used*/
	struct IP_entry ** ip_tmp = calloc(IP_ARR_SIZE + 1, sizeof(struct IP_entry));

	for (int i = 1; i <= IP_ARR_SIZE; ++i) {
		ip_tmp[i] = malloc(sizeof(struct IP_entry));
		ip_tmp[i]->count = 0;
		ip_tmp[i]->ts_index = 0;
		ip_tmp[i]->is_rejected = 0;
	}

	return ip_tmp;
}

void ip_update (struct IP_entry **ip_list, u_char index, char* source_ip, long int sec, long int usec) {
	ip_list[index]->count++;
	ip_list[index]->timestamps[ip_list[index]->ts_index] = sec;

	printf("26. satir %li\n", ip_list[index]->timestamps[ip_list[index]->ts_index]);
	printf("27. satir %li\n", (ip_list[index]->timestamps[((ip_list[index]->ts_index) + 1) % 50]));
	if ( ((ip_list[index]->timestamps[ip_list[index]->ts_index]) - (ip_list[index]->timestamps[((ip_list[index]->ts_index) + 1) % 50])) < 3 ) {
		printf("29. satir%li\n", ip_list[index]->timestamps[ip_list[index]->ts_index]);
	}


	/* if already rejected not enter*/
	if (ip_list[index]->is_rejected == 0 && ip_list[index]->count >= 50) {
		/*
		unsigned int a, b;
     
    	inet_pton (AF_INET, source_ip, &a);
    	inet_pton (AF_INET, "10.20.40.31", &b);
     	
     	
    	insert_rule ("filter",
                   "INPUT",
                   a,
                   0,
                   b,
                   1,
                   "REJECT");
        */


        char iptables_systemcall[] = "iptables -t filter -A INPUT -s ";
        strcat(iptables_systemcall, source_ip);
        strcat(iptables_systemcall, " -j REJECT --reject-with tcp-reset");

    	system(iptables_systemcall);

    	//ip_list[index]->count = 0;
    	ip_list[index]->is_rejected = 1;
	}
	(ip_list[index]->ts_index)++;
	(ip_list[index]->ts_index) %= 50;
}

void ip_free(struct IP_entry **ip_list) {
	if (ip_list) {
		for (int i = 0; i < IP_ARR_SIZE; ++i) {
			free(ip_list[i]);
		}
		free(ip_list);
	}
	
}

// iptables -A INPUT -s 65.55.44.100 -j DROP

/*
int main() {
	struct IP_entry** ip_list = ip_init();

	char ipsrc_tmp[16];
	strcpy(ipsrc_tmp, "10.20.40.1");
	char* token = strtok(ipsrc_tmp, ".");
	u_char count = 0;
	while (token) {
		if (count == 3) {
			u_char index = atoi(token);
			ip_list[index]->count++;
			ip_list[index]->arrival_time = (double)clock() / (double)CLOCKS_PER_SEC;
			printf("index = %d, count = %d, arrival_time = %f\n", index, ip_list[index]->count, ip_list[index]->arrival_time);
		}
		token = strtok(NULL, ".");
    	count++;
	}

	for (int i = 1; i <= IP_ARR_SIZE; ++i) {
		printf("%d %f\n", ip_list[i]->count, ip_list[i]->arrival_time);
	}


	return 0;
} */