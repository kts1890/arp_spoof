all: arp_spoof

arp_spoof: arp_spoof.cpp
	gcc -o arp_spoof arp_spoof.cpp -lpcap
clean: 
	rm -f arp_spoof

