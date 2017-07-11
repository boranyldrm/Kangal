<<<<<<< HEAD
---TCP SYN-FLOOD ATTACKING CODE---

*This project aims to create SYN packets with random source-IP numbers. *SYN packets are the first steps of a TCP-3-way handshake and by doing a SYN-flood attack, one can exhaust a server's sources and can block its data transmission. 
*Our code takes IP address and port number of the destination server which will be attacked. You can save your interface name on a .conf file for further developments. 
*Finally, after attack, created random IP addresses will be stored in a text file for further examination.

GETTING STARTED
*Download this c file from LINK. After compilation and running, you are supposed to enter interface name you are sending data through. (You can check yours via ipconfig (Windows users), ifconfig (Linux users), etc.)
*After that, enter IPv4 address you want to practice SYN-flood attack. (Do not forget to conform standard IPv4 syntax: x.x.x.x)
*Enter destination port number. 
*Hitting ENTER, attack begins...

RUNNING THE TESTS
*Be careful about the server's to which you attacked firewall subnetting protocols. For this code, we kept 10.20.50.0/24 as our subnet because our server was programmed to accept from only these IP addresses. You can edit/add more octets to your random IPs.
*You can trace your SYN packets by tcpdump (Linux) or Wireshark.
*Also you can specify SYN packets' quantity, duration through which they are sent. You only need to comment out necessary lines.
=======
# TCP-Syn-Flood-Defense

![alt text](https://github.com/boranyldrm/Kangal/blob/master/project_logo.jpeg?raw=true)

The first group will develop a code capable of attacking a tcp syn flood as detailed below. The other group will try to block and log this attack with the code they have developed on a server that does not have the ability to edit the OS kernel. You can use the netfilter module of the kernel as the engine on the blocking side, or you can add rules to iptables itself. You can write the codes in a programming language that you feel comfortable with. Python and Java are suitable, Bash / Shell is not accepted, it is extra nice if written in C.




Group 1:

As an argument, the host will receive ip and port information from the user. Interface name information can be written to the script as static, optionally the system itself can get it or read it from a conf file.
A class will be written that will randomly generate IP between 1-254 source host IP to be made the Syn flood, add S (Syn) every packet as tcp flag by randomly generating source port information. It will print the total number of packets sent to the screen.


Group 2

It will detect more than 50 Syn packets sent within 3 seconds of the same ip, reject these malicious ip addresses with Tcp RST, log in or print stdout. After 1 minute, the IP addresses will be redirected to the white list, and if the attack continues, the IP address will be blocked forever in a file that will be added to the blacklist.
>>>>>>> 9f9811bdf5529ba1f7d06e704dcc37b85fe3cdf0
