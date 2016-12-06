CFLAGS=-I../curl_wrapper/src -I../jsmn/ -ggdb -O0
LDFLAGS=-L../curl_wrapper/lib/curl-7.37.1/lib/.libs/ -L../jsmn -lcurl -ljsmn
CC=gcc

all: fxtr

fxtr: fxtr.c es.c
	$(CC) -o $@ $^ ../curl_wrapper/src/curl_wrapper.o $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf fxtr

check: clean all
	./test
