CC=gcc
EXEC = LeMookyScanner

all: $(EXEC)

LeMookyScanner: main.o ui.o utils.o scanner.o
	$(CC) main.o ui.o utils.o scanner.o -o $@

clean:
	-rm *.o

scanner.o: scanner.c scanner.h 
	$(CC) -c $<


utils.o: utils.c utils.h
	$(CC) -c $<

ui.o: ui.c ui.h scanner.h utils.h
	$(CC) -c $<

main.o: main.c ui.h
	$(CC) -c $<