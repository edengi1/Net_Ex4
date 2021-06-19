all: myping

myping: myping.o
	gcc -Wall -g myping.o -o myping

myping.o: myping.c
	gcc -Wall -g -c myping.c -o myping.o

.PHONY: clean all
	
clean: 
	rm *.o myping