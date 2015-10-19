# DNS-Traffic-Analysis

1.	Instructions to Compile and Run dnsdelay program.

Step 1: 	To compile the code from command line, type the following:
		g++ dnsdelay.cpp –o dsncpp –lpcap
Step 2:	To run the code from command line, type the following:
		./dnscpp cs691_homework1.pcap

2.	Following are the two traces captured as a part of second task.

o		Task2-Trace1.pcap – Here DNS server is chosen to be automatic.
o		Task2-Trace2.pcap – Google’s DNS server IP address is chosen as DNS server for local 	machine.

To run the program, after compiling with these traces, type the following two commands.

o		./dnscpp Task2-Trace1.pcap

o		./dnscpp Task2-Trace2.pcap
