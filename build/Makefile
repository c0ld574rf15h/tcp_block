EXE = tcp_block
CC = g++

$(EXE) : main.o
	$(CC) -o $(EXE) main.o -L ../bin -ltcpblock -lpcap -lglog

main.o : main.cpp
	$(CC) -o main.o -c main.cpp -I../include

clean:
	rm -f main.o $(EXE)