# GNU Keyring
#
# Copyright (C) 1999, 2000 by Martin Pool <mbp@humbug.org.au>
#
# $Id$

APP             = keyring
ICONTEXT        ="GNU Keyring"
APPID           = "Gtkr"

VERSION         = 1.1dev1
BUILD_DATE     := $(shell date +'%Y-%m-%d')

RCP             = $(APP).rcp
SRC             = keyring.c keyedit.c keydb.c memutil.c listform.c	\
		  crypto.c passwd.c uiutil.c generate.c prefs.c		\
		  export.c dbutil.c upgrade.c record.c category.c	\
		  beta.c setpasswd.c pwhash.c snib.c reencrypt.c	\
		  pack.c unpack.c sort.c

HEADERS	      = beta.h dbutil.h generate.h keyring.h passwd.h record.h	\
		upgrade.h category.h error.h keydb.h listform.h prefs.h	\
		resource.h util.h crypto.h export.h keyedit.h		\
		memutil.h pwhash.h uiutil.h snib.h pack.h unpack.h	\
		reencrypt.h sort.h

# 		  libdes/des_enc.c

DEP             = $(subst .c,.d,$(SRC))
OBJ		= $(subst .c,.o,$(SRC))
BIN             = $(APP).bin
DEF		= $(APP).def
EXE		= $(APP)

EN_PRC          = $(BASE)-en.prc

CC              = m68k-palmos-gcc
PILRC           = pilrc
TXT2BITM        = txt2bitm
BUILDPRC        = build-prc

BITMAPS         = keyring-15.xbm keyring-22.xbm 

# Note: 
# Turning on debugger support (-g) costs about 100 bytes

# Turning on  -finline-functions costs about 532 bytes
# Empirically the smallest executables come from -O2, which makes sense
# because it is defined to be the greatest amount of optimization that
# does not involve size-speed tradeoffs.

# Adding -O3 seems to make a difference to execution time as many
# functions are inlined.  However, it also generates code that
# greviously confuses gdb.  So, for debugging we turn optimization 
# off altogether and for ship versions we turn it right up.

# TODO: Switch optimization based on version number?

# On the other hand -O0 seems to make gcc not treat constants
# properly. Foo. 

DEFINES		= 
WARN	        = -Wall -Winline -Wunused -W	\
		-Wsign-compare -Wstrict-prototypes	\
		-Wmissing-prototypes -Winline		\
		-Wlarger-than-256 -Wshadow -Wcast-align	
OPTIM		= -O3 -finline-functions
# OPTIM		= -g
CFLAGS		= $(OPTIM) $(WARN) $(DEFINES) $(INCLUDES) -MMD 

HELP_TXT        = $(wildcard help/*/*.txt)

DOCS		= COPYING HACKING TODO TESTS 
# The web site is now maintained separately

DISTFILES       = $(RCP) $(RCP).in $(PRCS) Makefile $(BITMAPS) \
		  $(DOCS) $(SRC) $(HEADERS) $(DEF) \
		  $(HELP_TXT)

DIST_BALL	= $(APP)-$(VERSION).tar.gz
DIST_SIG        = $(DIST_BALL).asc
TAR		= tar

SED_SUBST        = -e "s/__VERSION__/$(VERSION)/g" \
		   -e "s/__DATE__/$(BUILD_DATE)/g"

BASE		= $(APP)-$(VERSION)

LANGUAGES = en de es sv

PRCS = $(foreach lang, $(LANGUAGES), $(BASE)-$(lang).prc)

default: $(BASE)-en.prc

all: $(PRCS) 

-include $(DEP)

$(BASE)-%.prc: %.resstamp $(EXE) $(DEF)
	cd res/$* && $(BUILDPRC) -o ../../$@ ../../$(DEF) ../../$(EXE) *.bin
	ls -l $@

%.resstamp: $(BITMAPS) resource.h 
%.resstamp: $(RCP)
	[ -d res/$* ] || mkdir -p res/$*
	-rm -f res/$*/*
	-rm -f *.bin
	$(PILRC) -H auto.h.tmp -q -L $* $(RCP) res/$*/
	cmp -s auto.h auto.h.tmp || mv auto.h.tmp auto.h
	touch $@

dist: $(DIST_BALL)

tmpdir:=$(shell echo _build.$$$$)
$(DIST_BALL): $(DISTFILES)
	rm -rf $(tmpdir)
	mkdir -p $(tmpdir)/$(BASE)
	cp --parents $(DISTFILES) $(tmpdir)/$(BASE)
	$(TAR) -C $(tmpdir) -czf $(DIST_BALL) $(BASE)
	ls -l $(DIST_BALL)
	rm -fr $(tmpdir)

# I hate accidentally editing the generated file, so the chmod 
# tries to discourage it
$(RCP): $(RCP).in Makefile
	rm -f $@
	(echo '// ******DYNAMICALLY GENERATED DO NOT EDIT********'; \
	 sed $(SED_SUBST) $@.in) > $@
	chmod -w $@

$(EXE):       $(SRC:.c=.o) ;
	$(CC) $(CFLAGS) $^ -o $(EXE)

# We try to avoid touching auto.h, because that will kick off
# rebuilding a lot of source and it's often not necessary.
auto.h: en.resstamp

%.s: %.c
	$(CC) $(CFLAGS) -S $< 

%.o: %.c auto.h
	$(CC) $(CFLAGS) -c $< -o $*.o

clean:
	rm -f *.o $(EXE) *.bin res/*/* *.grc *.prc *.resstamp *.bin *.d *.stamp

tags: TAGS
TAGS: *.c *.h
	etags *.c *.h

# for the GNU id-tools package: 
ID: .
	mkid

.PHONY: install

install: $(EN_PRC)
	pilot-xfer -i $(EN_PRC)
