CC=cc
#USESSL=openssl
USESSL=mbed

#CFLAGS=-Wall -Wpointer-arith -O2 -g -fsanitize=address -mtune=core2
CFLAGS=-Wall -Wpointer-arith -O2 -g -fno-stack-protector -fomit-frame-pointer -mtune=core2 -DPCLOUD_TESTING

ifeq ($(OS),Windows_NT)
    CFLAGS += -DP_OS_WINDOWS
else
    UNAME_S := $(shell uname -s)
    UNAME_V := $(shell uname -v)
    ifeq ($(UNAME_S),Linux)
        CFLAGS += -DP_OS_LINUX
            ifneq (,$(findstring Debian,$(UNAME_V)))
                CFLAGS += -DP_OS_DEBIAN
            endif
	LDFLAGS += -lssl -lcrypto -lpthread
    endif
    ifeq ($(UNAME_S),Darwin)
        CFLAGS += -DP_OS_MACOSX -I/usr/local/ssl/include/
        CFLAGS += -DP_OS_MACOSX -I/usr/local/include/osxfuse/
	LDFLAGS += -lssl -lcrypto -lpthread -L/usr/local/ssl/lib
        #USESSL=securetransport
    endif
endif

OBJ=overlay_client.o  debug.o

all: overlay_client

fs: overlay_client

overlay_client: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o overlay_client

clean:
	rm -f *~ *.o

