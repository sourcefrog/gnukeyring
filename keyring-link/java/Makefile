LIBJAVA=net/sf/astroinfo/pdb/*.java \
        net/sf/gnukeyring/*.java \
        net/sf/gnukeyring/decoder/*.java

EXPORTJAVA=net/sf/gnukeyring/export/*.java \
	com/Ostermiller/util/*.java

LIBCLASS=$(LIBJAVA:%.java=%.class)
EXPORTCLASS=$(EXPORTJAVA:%.java=%.class)

all: export.jar
.PHONY: force


export.jar: force
	javac $(LIBJAVA) $(EXPORTJAVA)
	jar -cfe export.jar net.sf.gnukeyring.export.Export $(LIBCLASS) $(EXPORTCLASS)
	jar -cfe export-src.jar $(LIBJAVA) $(EXPORTJAVA)