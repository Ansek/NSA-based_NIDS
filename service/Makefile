LIBS = -lwsock32

all: nsa-based_nids_service

test: TestAlgorithm

nsa-based_nids_service: settings.o filemanager.o algorithm.o analyzer.o sniffer.o main.o
	gcc settings.o filemanager.o algorithm.o analyzer.o sniffer.o main.o $(LIBS) -o nsa-based_nids_service.exe

TestAlgorithm: settings.o filemanager.o algorithm.o unity.o TestAlgorithm.o 
	@gcc settings.o filemanager.o algorithm.o unity.o TestAlgorithm.o -o TestAlgorithm.exe
	@echo TestAlgorithm:
	@TestAlgorithm.exe

TestAlgorithm.o: tests\TestAlgorithm.c
	gcc -c tests\TestAlgorithm.c	

unity.o: tests\src\unity.c
	gcc -c tests\src\unity.c
	
settings.o: settings.c
	gcc -c settings.c

filemanager.o: filemanager.c
	gcc -c filemanager.c

algorithm.o: algorithm.c
	gcc -c algorithm.c
	
analyzer.o: analyzer.c
	gcc -c analyzer.c
	
sniffer.o: sniffer.c
	gcc -c sniffer.c

main.o: main.c
	gcc -c main.c

clean:
	del /F /Q *.o *.exe