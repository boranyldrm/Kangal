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
		ip_tmp[i]->arrival_time = 0;
	}

	return ip_tmp;
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