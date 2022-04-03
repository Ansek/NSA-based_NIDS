all: nsa-based_nids_service

nsa-based_nids_service: main.o settings.o
	gcc main.o settings.o -o nsa-based_nids_service

main.o: main.c
	gcc -c main.c

settings.o: settings.c
	gcc -c settings.c
	
clean:
	rm -rf *.o *.exe