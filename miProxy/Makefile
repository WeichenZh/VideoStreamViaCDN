CC=gcc
CXX=g++
RM=rm -f
LDFLAGS = -g -std=c++11

all: main

main: main.o session.o
	$(CXX) $(LDFLAGS) -o myProxy main.o session.o 

main.o: main.cpp session.h
	$(CXX) $(LDFLAGS) -c main.cpp

session.o: session.h
	$(CXX) $(LDFLAGS) -c session.cpp

clean:
	$(RM) main.o session.o myProxy
