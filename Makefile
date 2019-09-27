all : pcap_test

pcap_test: main.o pcap.o
	g++ -g -o pcap_test main.o pcap.o -lpcap

main.o: main.cpp
	g++ -g -c -o main.o main.cpp

pcap.o: pcap.cpp pcap.h
	g++ -c -o pcap.o pcap.cpp

clean:
	rm -f pcap_test
	rm -f *.o
