all:
	gcc -c -g -o memstat.o memstat.c 
	ar r libmemstat.a memstat.o
	gcc -g main.c libmemstat.a -ldl -lbfd
clean:
	rm -f *.o *.so *.a a.out
