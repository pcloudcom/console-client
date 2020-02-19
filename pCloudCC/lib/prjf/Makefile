#CC=clang
CC=gcc
#CFLAGS      = -fPIC -g #-pedantic -Wall -Wextra -ggdb3
#LDFLAGS     =-lz -ldl -lpmobile -Lpmobile -lmbedtls -lfuse -lpthread -Llibs/mbedtls/library
#LDFLAGS      =-lsqlite3 -lmbedtls -L../pclsync/lib/mbedtls/library -lcrypto -lpthread -ldl -lfuse -lz ./lib/jsmn/jsmn.o
LDFLAGS      =-lsqlite3 -lmbedtls -L../pclsync/lib/mbedtls/library -lcrypto -lpthread -ldl -lfuse -lz 

LIBPATH      =../pclsync

SHAREFLAGS   =-shared

DEBUGFLAGS   =-O0 -D _DEBUG
RELEASEFLAGS =-O2 -D NDEBUG -combine -fwhole-program

USESSL       =mbedtls

#CFLAGS=-Wall -Wpointer-arith -g -O2 -fsanitize=address
#CFLAGS=-Wall -Wpointer-arith -g -fPIC -I./pmobile
#CFLAGS       =-Wall -Wpointer-arith -g -fPIC -I./lib/jsmn -I./lib/curl/include -I$(LIBPATH) -DP_ELECTRON
CFLAGS       =-Wall -Wpointer-arith -g -fPIC  -I$(LIBPATH) -DP_ELECTRON
#CFLAGS=-Wall -Wpointer-arith -g -O2

TARGET       =pRJF.so

#DYNLIBS      =-rdynamic ./$(TARGET) -rdynamic ./lib/curl/lib/libcurl.so
DYNLIBS      =-rdynamic ./$(TARGET)

STAT_LIBS    =$(LIBPATH)/psynclib.a

OBJ=pRJF.o lib/jsmn/jsmn.o

#all: $(TARGET) test libs/jsmn/jsmn.o
all: $(TARGET)

libcurl:
	cd lib/curl && cmake . && $(MAKE)

#libs/jsmn/jsmn.o: 
#	$(CC) $(SHAREFLAGS) $(CFLAGS) $(DEBUGFLAGS)  ./lib/jsmn/jsmn.c -o ./lib/jsmn/jsmn.o

#$(TARGET): $(OBJ)
#	$(LINK.c) -shared $< -o $@
$(TARGET): $(OBJ)
	$(CC) $(SHAREFLAGS) $(CFLAGS) $(DEBUGFLAGS) -o $(TARGET) $(OBJ) $(STAT_LIBS)
	
#test: test.o $(TARGET)
#	$(CC) test.c  $(DYNLIBS) $(CFLAGS) $(LDFLAGS) $(DEBUGFLAGS) $(STAT_LIBS) -o test
	

clean:
	rm -f *~ *.o $(TARGET) ./test 

#&& cd libs/mbedtls && $(MAKE) clean && cd ../.. && cd pmobile && $(MAKE) clean

