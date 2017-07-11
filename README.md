# TCP Syn-Flood Attacking and Defending


![alt text](https://github.com/boranyldrm/Kangal/blob/master/logo.png?raw=true)

Two groups of codes are to develop a code capable of attacking and defending a tcp-syn flood as detailed below. The defending group will try to block and log this attack with the code they have developed on a server that does not have the ability to edit the OS kernel. Netfilter module of the kernel is used as the engine on the blocking side, and new rules are added to iptables. Codes are written in C. 


Attacking Group:
----------------

As argument, the destination IP and port information will be received from the user. Interface name information is written to a conf file.
Random IP numbers between 1-254 are generated as source host IP to be used with the Syn flood, S (Syn) flag is added to every packet as tcp flag by randomly generating source port information. It will print the total number of packets sent to the screen.

Defending Group:
----------------

The code will detect more than 50 Syn packets sent within 3 seconds of the same IP, reject these malicious ip addresses with TCP RST, log in or print stdout. After 1 minute, the IP addresses will be redirected to the white list, and if the attack continues, the IP address will be blocked forever in a file that will be added to the blacklist.
