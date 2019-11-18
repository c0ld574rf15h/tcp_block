EXE = tcp_block
CC = g++

$(EXE) : main.o
	$(CC) -L ../bin -o $(EXE) main.o -ltcpblock -lpcap -lglog

main.o : main.cpp
	$(CC) -o main.o -c -I../include main.cpp

clean:
	rm -f main.o $(EXE)