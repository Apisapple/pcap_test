all : pcap_test

pcap_test: main.o pcap_test.o
	g++ -g -o pcap_test main.o pcap_test.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

pcap_test.o:
	g++ -g -c -o pcap_test.o pcap_test.cpp

clean:
	rm -f pcap_test
	rm -f *.o

