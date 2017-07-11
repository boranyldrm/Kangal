#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>


/* seconds and microseconds of the entry*/
struct IP_timestamp {
	long int sec;
	long int usec;
};

#ifndef IP_ENTRY_H
#define IP_ENTRY_H
struct IP_entry {
	u_int count;	/* how many packets are received from this IP*/
	struct IP_timestamp timestamps[50];		/* circular array contains the arrival time of last 50 packets from this IP */
	u_char ts_index;	/* current index of timestamps circular array */
	u_char is_rejected;	/*if the ip is rejected then 1, not rejected 0, blacklist 2 */
};
#endif

#define IP_ARR_SIZE 254	/* 254 host ip 10.20.40.* (0 and 255 excluded)*/ 

/* create new IP_entry in ip_list */
struct IP_entry** ip_init ();

/* Reset the ip_entry */
void ip_reset (struct IP_entry **ip_list, u_char index);

/* update the entry values  in the specific index*/
void ip_update (struct IP_entry **ip_list, u_char index, char* source_ip, long int sec, long int usec, char can_drop);

/* deallocation of the memory spaces */
void ip_free (struct IP_entry **ip_list);
