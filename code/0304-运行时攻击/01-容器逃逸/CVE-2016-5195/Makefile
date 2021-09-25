CFLAGS := -Wall
LDFLAGS := -lpthread

all: 0xdeadbeef

0xdeadbeef: 0xdeadbeef.o
	$(CC) -o $@ $^ $(LDFLAGS)

0xdeadbeef.o: 0xdeadbeef.c payload.h
	$(CC) -o $@ -c $< $(CFLAGS)

payload.h: payload
	xxd -i $^ $@

payload: payload.s
	nasm -f bin -o $@ $^

clean:
	rm -f *.o *.h 0xdeadbeef