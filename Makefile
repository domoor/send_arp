all: send_arp

send_arp: main.o
	gcc -o send_arp main.o -lpcap

main.o:
	gcc -o main.o -c main.c

clean:
	rm -f send_arp
	rm -f *.o

