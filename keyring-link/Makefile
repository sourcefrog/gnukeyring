CFLAGS = -g -Wall -D'PACKAGE="keyring-link"'
LIBS = -lpisock -lcrypto

OBJS = keyring.o trace.o

keyring-link: $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

