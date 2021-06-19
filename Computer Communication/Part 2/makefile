all: sniffer

sniffer: sniffer.o
	gcc -Wall -g sniffer.o -o sniffer

myping.o: myping.c
	gcc -Wall -g -c sniffer.c -o sniffer.o

.PHONY: clean all
	
clean: 
	rm *.o sniffer