all : pcap_test

pcap_test: main.o pcap.o
	g++ -Wall -g -o pcap_test main.o pcap.o -lpcap

main.o: main.cpp
	g++ -Wall -g -c -o main.o main.cpp

pcap.o: pcap.cpp pcap.h
	g++ -Wall -c -o pcap.o pcap.cpp

clean:
	rm -f pcap_test
	rm -f *.o
