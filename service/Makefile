LIBS = -lwsock32

all: nsa-based_nids_service

nsa-based_nids_service: main.o settings.o sniffer.o
	gcc main.o settings.o sniffer.o $(LIBS) -o nsa-based_nids_service

main.o: main.c
	gcc -c main.c

settings.o: settings.c
	gcc -c settings.c
	
sniffer.o: sniffer.c
	gcc -c sniffer.c

clean:
	rm -rf *.o *.exe