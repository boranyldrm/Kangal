TCP SYN-FLOOD DEFENCING CODE
============================

* This project aims to capture the SYN packets and detect the attackers IP addresses and block them from the system.
* SYN packets are the first steps of a TCP-3-way handshake and by running the SYN-flood defence software, prevent the server's resources from being used too high. 
* If this software is not run in such an attack then your server would not respond due to the high volume network connections and processes. 
* Finally, in an attack, the IP addresses first will be rejected with tcp-reset by iptables and then if the rejected IP address continues to send packets the IP address connection is dropped by iptables.


GETTING STARTED
---------------

* After downloading the Kangal change directory to /Defence folder. When you call __make__ and then __make run__ the defence will start to run on your server.
* You can modify the defence.conf file for your specific requirements.

RUNNING THE TESTS
-----------------

* If the tcpdump is open and you start the attack code, you will see lots of SYN packets and after you run defence code in iptables you can see the rejected and dropped IP addresses.

VIDEOS
------