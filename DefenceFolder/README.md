# TCP-Syn-Flood-Defense

The first group will develop a code capable of attacking a tcp syn flood as detailed below. The other group will try to block and log this attack with the code they have developed on a server that does not have the ability to edit the OS kernel. You can use the netfilter module of the kernel as the engine on the blocking side, or you can add rules to iptables itself. You can write the codes in a programming language that you feel comfortable with. Python and Java are suitable, Bash / Shell is not accepted, it is extra nice if written in C.




Group 1:

As an argument, the host will receive ip and port information from the user. Interface name information can be written to the script as static, optionally the system itself can get it or read it from a conf file.
A class will be written that will randomly generate IP between 1-254 source host IP to be made the Syn flood, add S (Syn) every packet as tcp flag by randomly generating source port information. It will print the total number of packets sent to the screen.


Group 2

It will detect more than 50 Syn packets sent within 3 seconds of the same ip, reject these malicious ip addresses with Tcp RST, log in or print stdout. After 1 minute, the IP addresses will be redirected to the white list, and if the attack continues, the IP address will be blocked forever in a file that will be added to the blacklist.
