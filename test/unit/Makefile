CFLAGS	= -I../../include -D_FILE_OFFSET_BITS=64
OFLAGS	= -O
LDFLAGS	= -L../../library -ltropicssl -lcheck -lc -lrt -lm -lpthread

OBJS	= 	tropicssl_unittests.o		\
			aes/check_aes.o

all: tropicssl_unittests

tropicssl_unittests: $(OBJS)
	$(CC) $(CFLAGS) $(OFLAGS) $(OBJS)   $(LDFLAGS) -o $@

.c.o:
	echo "  CC    $<"
	$(CC) $(CFLAGS) $(OFLAGS) -c $<

aes/check_aes.o: aes/check_aes.c ../../library/libtropicssl.a
	echo   "  CC    aes/check_aes.c"
	$(CC) $(CFLAGS) $(OFLAGS) -c aes/check_aes.c -o $@

clean:
	rm -f $(OBJS) tropicssl_unittests