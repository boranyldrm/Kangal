#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};

//checksum is needed for socket transmission. Sockets without checksum calculations are not accepted by destination.
 
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

//used for checking IP number's validity.
int isInteger(char *str){
    for(int i=0;i<strlen(str);i++){
	if(isdigit(str[i])==0&&str[i]!='\n'){
	   return 0;
	}
    }
    return 1;
}

//checks if IP number is valid
int check_IP(char *IP){
    int num;
    int flag=1;
    int counter=0;

    char* p=strtok(IP, ".");
    
    while(p!=NULL){
	if(isInteger(p)){
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
	else{
	    flag=0;
	    break;
	}
     }
     return flag&&counter==4;
}
