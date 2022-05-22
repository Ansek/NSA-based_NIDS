LIBS = -lwsock32

all: nsa-based_nids_service

nsa-based_nids_service: main.o settings.o filemanager.o analyzer.o sniffer.o
	gcc main.o settings.o filemanager.o analyzer.o sniffer.o $(LIBS) -o nsa-based_nids_service

main.o: main.c
	gcc -c main.c

settings.o: settings.c
	gcc -c settings.c

filemanager.o: filemanager.c
	gcc -c filemanager.c
	
analyzer.o: analyzer.c
	gcc -c analyzer.c
	
sniffer.o: sniffer.c
	gcc -c sniffer.c

clean:
	rm -rf *.o *.exe