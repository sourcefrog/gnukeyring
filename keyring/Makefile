# Copyright (C) 1999, 2000 by Martin Pool
# $Id$

APP             = keyring
ICONTEXT        ="Keyring"
APPID           = "Gtkr"

VERSION         = 0.9.0-dev

RCP             = $(APP).rcp
PRC             = $(APP)-$(VERSION).prc
SRC             = keyring.c keyedit.c keydb.c memutil.c listform.c \
		  crypto.c passwd.c uiutil.c generate.c prefs.c \
		  export.c dbutil.c
DEP             = $(subst .c,.d,$(SRC))
OBJ		= $(subst .c,.o,$(SRC))
#GRC             = $(APP).grc
BIN             = $(APP).bin
DEF		= $(APP).def
EXE		= $(APP)

NM		= m68k-palmos-nm
CC              = m68k-palmos-gcc
PILRC           = pilrc
TXT2BITM        = txt2bitm
# OBJRES          = m68k-palmos-obj-res
BUILDPRC        = build-prc

HELP_TXT	= delete-confirm.txt generate-help.txt preferences-help.txt
BITMAPS         = keyring-15.xbm keyring-22.xbm philosophical-gnu-tiny-bw.bmp

# Note: 
# Turning on debugger support (-g) costs about 100 bytes
# Turning on  -finline-functions costs about 532 bytes
# Empirically the smallest executables come from -O2, which makes sense
# because it is defined to be the greatest amount of optimization that
# does not involve size-speed tradeoffs.

CFLAGS          = -O2 -Wall -Werror -Winline -Wno-unused -W \
		  $(DEFINES) $(INCLUDES) -MMD -g

TOP_DOCS	= HACKING COPYING BUGS TODO TESTS 
DOCS		= $(TOP_DOCS) \
		  doc/break.html doc/find.html doc/index.html \
		  doc/memo-import-export.html doc/security.html \
		  doc/attack-tree.txt doc/description.txt \
		  doc/Blatant-Plug-Insert-4-Cheap.jpg \
		  doc/keyring.css

DISTFILES       = $(RCP) $(PRC) Makefile $(HELP_TXT) $(BITMAPS) \
		  $(DOCS) $(wildcard *.c *.h)

DIST_BALL	= $(APP)-$(VERSION).tar.gz
DIST_SIG        = $(DIST_BALL).asc
TAR		= tar

SED_SUBST        = -e "s/__VERSION__/$(VERSION)/g" \
		   -e "s/__DIST_BALL__/$(DIST_BALL)/g"

all: $(DOCS) $(PRC) 

include .dependencies

PRC: $(PRC)

$(PRC):   $(EXE) $(DEF)      bin.stamp
	$(BUILDPRC) -o $(PRC) $(DEF) $(EXE) *.bin 
	ls -l *.prc

dist: $(DIST_BALL)

$(DIST_BALL): $(DISTFILES)
	$(TAR) -C .. -czf $(DIST_BALL) $(addprefix $(APP)/,$(DISTFILES))
	ls -l $(DIST_BALL)

.SUFFIXES: .in

keyring.rcp: keyring.rcp.in Makefile
	(echo '// ******DYNAMICALLY GENERATED DO NOT EDIT********'; \
	 sed $(SED_SUBST) $@.in) > $@

#grc.stamp:    $(APP) ;
#	$(OBJRES) $(APP)
#	touch $@

$(EXE):       $(SRC:.c=.o) ;
	$(CC) $(CFLAGS) $^ -o $(EXE)

bin.stamp:    $(RCP) $(BITMAPS) resource.h $(HELP_TEXT)
	[ -d res ] || mkdir res
	-rm *.bin
	$(PILRC) -q $(RCP) 
	touch $@

%.o %.d: %.c ;
	$(CC) $(CFLAGS) -c $< -o $*.o

depend dep: ;
	$(CC) -M $(SRC) > .dependencies

clean:
	rm -rf *.o $(EXE) *.bin *.grc *.prc *.stamp *.bin *.d *.stamp

.PHONY: install

install: $(PRC)
	pilot-xfer -i $(PRC)

# Only useful for the maintainer
.PHONY: _upload
hosting_dir = gnukeyring.sourceforge.net:/home/groups/gnukeyring/htdocs
upload_doc: $(DOCS)
	rsync --times -e ssh -v $(DOCS) $(hosting_dir) 

sig: $(DIST_SIG)

$(DIST_SIG): $(DIST_BALL)
	gpg -u 40C90109 -a -b $(DIST_BALL)

# TODO: Also upload the release to the SourceForge download area

count: 
	@cat *.[ch] *.rcp Makefile|wc -l

tags: TAGS
TAGS: *.c *.h
	etags *.c *.h

# for the GNU id-tools package: 
ID: .
	mkid

# this target is really just for my use. It only works on a limited
# range of machines and is used to produce a list of potentially
# dead (ie. unused) functions in the code. (tridge)
finddead: $(OBJ)
	$(NM) $(OBJ) |grep 'U ' | awk '{print $$2}' | sort -u > nmused.tmp
	$(NM) $(OBJ) |grep 'T ' | awk '{print $$3}' | sort -u > nmfns.tmp
	comm -13 nmused.tmp nmfns.tmp
