nameserver : nameserver.o RR_loader.o Geo_loader.o Dijkstra.o
	g++ -o nameserver nameserver.o RR_loader.o Geo_loader.o Dijkstra.o

nameserver.o : nameserver.cpp RR_loader.h Geo_loader.h error_msg.h
	g++ -c nameserver.cpp

RR_loader.o :  RR_loader.cpp DNSHeader.h DNSQuestion.h DNSRecord.h error_msg.h
	g++ -c RR_loader.cpp

Geo_loader.o :  Geo_loader.cpp Dijkstra.h DNSHeader.h DNSQuestion.h DNSRecord.h error_msg.h
	g++ -c Geo_loader.cpp

Dijkstra.o : Dijkstra.cpp Dijkstra.h
	g++ -c Dijkstra.cpp

clean: 
	rm -f nameserver nameserver.o RR_loader.o Geo_loader.o Dijkstra.o
