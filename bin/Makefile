CC = g++
ARC = libtcpblock.a
OBJ = packet.o

$(ARC) : $(OBJ)
	$(AR) $(ARFLAGS) $@ $(OBJ)

%.o : %.cpp
	$(CC) -o $@ -c -I../include $<

clean:
	rm -f *.o $(ARC)