# Copyright (C) 1999, 2000 by Martin Pool
# $Id$

APP             = keyring
ICONTEXT        ="Keyring"
APPID           = "Gtkr"

VERSION         = 0.13.0

RCP             = $(APP).rcp
SRC             = keyring.c keyedit.c keydb.c memutil.c listform.c \
		  crypto.c passwd.c uiutil.c generate.c prefs.c \
		  export.c dbutil.c upgrade.c record.c category.c \
# 		  libdes/des_enc.c

DEP             = $(subst .c,.d,$(SRC))
OBJ		= $(subst .c,.o,$(SRC))
#GRC             = $(APP).grc
BIN             = $(APP).bin
DEF		= $(APP).def
EXE		= $(APP)

xNM		= m68k-palmos-nm
CC              = m68k-palmos-gcc
PILRC           = pilrc
TXT2BITM        = txt2bitm
# OBJRES          = m68k-palmos-obj-res
BUILDPRC        = build-prc

BITMAPS         = keyring-15.xbm keyring-22.xbm philosophical-gnu-tiny-bw.bmp

# Note: 
# Turning on debugger support (-g) costs about 100 bytes
# Turning on  -finline-functions costs about 532 bytes
# Empirically the smallest executables come from -O2, which makes sense
# because it is defined to be the greatest amount of optimization that
# does not involve size-speed tradeoffs.

# -Wconversion

DEFINES		= -DPALM_KEYRING
CFLAGS          = -O2 -Wall -Werror -Winline -Wunused -W \
		   -Wsign-compare -Wstrict-prototypes \
		  -Wmissing-prototypes \
		  $(DEFINES) $(INCLUDES) -MMD -g

HELP_TXT        = $(wildcard help/*/*.txt)

DOCS		= COPYING HACKING TODO TESTS 
# The web site is now maintained separately

DISTFILES       = $(RCP) $(RCP).in $(PRCS) Makefile $(BITMAPS) \
		  $(DOCS) $(wildcard *.c *.h) $(DEF) \
		  $(HELP_TXT)

DIST_BALL	= $(APP)-$(VERSION).tar.gz
DIST_SIG        = $(DIST_BALL).asc
TAR		= tar

SED_SUBST        = -e "s/__VERSION__/$(VERSION)/g" \
		   -e "s/__DIST_BALL__/$(DIST_BALL)/g"

BASE		= $(APP)-$(VERSION)

LANGUAGES = en de es

PRCS = $(foreach lang, $(LANGUAGES), $(BASE)-$(lang).prc)

all: $(DOCS) $(PRCS) 

include $(DEP)

$(BASE)-%.prc: %.resstamp $(EXE) $(DEF)
	cd res/$* && $(BUILDPRC) -o ../../$@ ../../$(DEF) ../../$(EXE) *.bin
	ls -l $@

dist: $(DIST_BALL)

$(DIST_BALL): $(DISTFILES)
	$(TAR) -C .. -czf $(DIST_BALL) $(addprefix $(APP)/,$(DISTFILES))
	ls -l $(DIST_BALL)

$(RCP): $(RCP).in Makefile
	(echo '// ******DYNAMICALLY GENERATED DO NOT EDIT********'; \
	 sed $(SED_SUBST) $@.in) > $@

$(EXE):       $(SRC:.c=.o) ;
	$(CC) $(CFLAGS) $^ -o $(EXE)

%.resstamp: $(RCP) $(BITMAPS) resource.h 
	[ -d res/$* ] || mkdir -p res/$*
	-rm -f res/$*/*
	-rm -f *.bin
	$(PILRC) -q -L $* $(RCP) res/$*/
	touch $@

%.s: %.c
	$(CC) $(CFLAGS) -S $< 

%.o %.d: %.c ;
	$(CC) $(CFLAGS) -c $< -o $*.o

depend: $(DEP)

clean:
	rm -rf *.o $(EXE) *.bin res/*/* *.grc *.prc *.stamp *.bin *.d *.stamp

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
