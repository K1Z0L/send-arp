LDLIBS=-lpcap

all: send-arp

send-arp: main.o ip.o mac.o
	g++ $^ $(LDLIBS) -g -o $@

clean:
	rm -f send-arp *.o