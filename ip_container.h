#include <time.h>
#include <stdlib.h>
#include <sys/types.h>

#ifndef IP_ENTRY_H
#define IP_ENTRY_H
struct IP_entry {
	u_char count;
	double arrival_time;
};
#endif

#define IP_ARR_SIZE 254	/* 254 host ip 10.20.40.* (0 and 255 excluded)*/ 

/* create new IP_entry in ip_list */
struct IP_entry** ip_init ();

/* Reset the ip_entry */
void ip_reset (struct IP_entry **ip_list, u_char index);

/* update the entry values  in the specific index*/
void ip_update (struct IP_entry **ip_list, u_char index);