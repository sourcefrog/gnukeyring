OPENSSL_HOME=../openssl-0.9.7/usr

CFLAGS = -g -Wall -D'PACKAGE="keyring-link"'
LIBS = -lpisock -lcrypto

ifdef OPENSSL_HOME
CFLAGS += -I$(OPENSSL_HOME)/include
LIBS += -L$(OPENSSL_HOME)/lib
endif

KEYRINGJAVA = KeyringEntry KeyringLibrary \
              export/Export export/XMLExport export/CSVExport \
              decoder/PDBKeyringLibrary \
	      decoder/PDBKeyringEntry decoder/PDBKeyringEntry5
PDBJAVA =    Database PalmDataInputStream PalmDataOutputStream \
	     Record PDBRecord PRCRecord \
	     AppInfoBlock SortInfoBlock \
	     CreateOverlay
CSVJAVA =    CSVPrint ExcelCSVPrinter StringHelper \
	     BadLineEndingException BadDelimiterException \
	     BadQuoteException BadDelimeterException

CLASSES = $(KEYRINGJAVA:%=java/net/sf/gnukeyring/%.class) \
	  $(PDBJAVA:%=java/net/sf/astroinfo/pdb/%.class) \
	  $(CSVJAVA:%=java/com/Ostermiller/util/%.class)

OBJS = keyring.o keyring5.o trace.o hextype.o

all: keyring-link export.jar export-src.jar
keyring-link: $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

export.jar: $(CLASSES)
	cd java; \
	jar cfe ../$@ net.sf.gnukeyring.export.Export `find -name \*.class`

export-src.jar: $(CLASSES:%.class=%.java)
	cd java; \
	jar cfe ../$@ $(CLASSES:java/%.class=%.java)

$(CLASSES): %.class: %.java
	javac -d java -cp java $^

install: keyring-link
	install keyring-link $(DESTDIR)/usr/bin/

clean: 
	rm -f keyring-link *.jar $(OBJS) `find -name \*.class`

.PHONY: install clean

