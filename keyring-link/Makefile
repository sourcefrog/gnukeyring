OPENSSL_HOME=../openssl-0.9.7/usr

CFLAGS = -g -Wall -D'PACKAGE="keyring-link"'
LIBS = -lpisock -lcrypto

ifdef OPENSSL_HOME
CFLAGS += -I$(OPENSSL_HOME)/include
LIBS += -L$(OPENSSL_HOME)/lib
endif


OBJS = keyring.o keyring5.o trace.o hextype.o

all: keyring-link
keyring-link: $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

install: keyring-link
	install keyring-link $(DESTDIR)/usr/bin/

clean: 
	rm -f keyring-link $(OBJS)

.PHONY: install clean

