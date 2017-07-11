TCP SYN-FLOOD ATTACKING CODE
============================

* This project aims to create SYN packets with random source-IP numbers.
* SYN packets are the first steps of a TCP-3-way handshake and by doing a SYN-flood attack, one can exhaust a server's sources and can block its data transmission. 
* Our code takes IP address and port number of the destination server which will be attacked. You can save your interface name on a .conf file for further developments. 
* Finally, after attack, created random IP addresses will be stored in a text file for further examination.

GETTING STARTED
---------------

* Download this c file from https://github.com/boranyldrm/Kangal. After compilation and running, you are supposed to enter interface name you are sending data through. (You can check yours via ipconfig (Windows users), ifconfig (Linux users), etc.)
* After that, enter IPv4 address you want to practice SYN-flood attack. (_Do not forget to conform standard IPv4 syntax: x.x.x.x_)
* Enter destination port number. 
* Hitting ENTER, attack begins...

RUNNING THE TESTS
-----------------

* Be careful about the server's to which you attacked firewall subnetting protocols. For this code, we kept 10.20.50.0/24 as our subnet because our server was programmed to accept from only these IP addresses. You can edit/add more octets to your random IPs.
* You can trace your SYN packets by tcpdump (Linux) or Wireshark.
* Also you can specify SYN packets' quantity, duration through which they are sent. You only need to comment out necessary lines.

VIDEOS
------

* For application videos, you can visit: [![Watch the SYN-Flood Attacking video]()](https://youtu.be/ciHMhSGKe7A)
* For storage files' content, you can visit: [![Watch the Contents of interface and IPNumbers video]()](https://youtu.be/nTcuAT4HJQQ)
