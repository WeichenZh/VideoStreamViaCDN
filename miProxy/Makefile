CC=gcc
CXX=g++
RM=rm -f
LDFLAGS = -g -std=c++11
TP=../starter_files/
TOOLS=$(wildcard $(TP)*.h)

all: main

main: main.o session.o dns_sender.o
	$(CXX) $(LDFLAGS) -o miProxy main.o session.o dns_sender.o

main.o: main.cpp session.h
	$(CXX) $(LDFLAGS) -c main.cpp

session.o: session.h dns_sender.h
	$(CXX) $(LDFLAGS) -c session.cpp

dns_sender.o: dns_sender.h $(TOOLS)
	$(CXX) $(LDFLAGS) -c -I$(TP) dns_sender.cpp

clean:
	$(RM) *.o miProxy
