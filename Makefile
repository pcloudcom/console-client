CC=cc
AR=ar rcu
RANLIB=ranlib

CFLAGS=-Wall -g -O2

LIB_A=psynclib.a

ifeq ($(OS),Windows_NT)
    CFLAGS += -DWINDOWS
    LIB_A=psynclib.dll
    AR=$(CC) -shared -o
    RANLIB=strip --strip-unneeded
    LDFLAGS=-s
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        CFLAGS += -DLINUX
    endif
    ifeq ($(UNAME_S),Darwin)
        CFLAGS += -DMACOSX
    endif
endif

OBJ=pcompat.o psynclib.o plibs.o pcallbacks.o pdiff.o

all: $(LIB_A)

$(LIB_A): $(OBJ)
	$(AR) $@ $(OBJ)
	$(RANLIB) $@

clean:
	rm -f *~ *.o $(LIB_A)

