# Keyring for PalmOS.  
# 
# Resource file to be preprocessed.
#
# Copyright (C) 1999, 2000, 2001 by Martin Pool <mbp@users.sourceforge.net>
#
# $Header$

APP             = keyring
ICONTEXT        = "Keyring"
APPID           = "Gtkr"

# XXX: You may have to edit this to match your SDK installation
#PALM_BASE       = /usr/local/include/palmos3.5
#C_INCLUDE_PATH  = $(PALM_BASE):$(PALM_BASE)/Core:$(PALM_BASE)/Core/Hardware:$(PALM_BASE)/Core/System:$(PALM_BASE)/Core/UI
#export C_INCLUDE_PATH

VERSION         = 1.1pre4
BUILD_DATE     := $(shell date +'%Y-%m-%d')

RCP             = $(APP).rcp
RCP_IN          = $(RCP).ja $(RCP).in
BITMAPS         = keyring-15.xbm keyring-22.xbm lock.xbm unlock.xbm
RESOURCES	= fontPW.txt fontstar.txt $(BITMAPS)
SRC             = keyring.c keyedit.c keydb.c memutil.c listform.c	\
		  crypto.c passwd.c uiutil.c generate.c prefs.c		\
		  export.c dbutil.c upgrade.c record.c category.c	\
		  beta.c setpasswd.c pwhash.c snib.c reencrypt.c	\
		  pack.c unpack.c sort.c secrand.c debug.c

HEADERS	      = keyring.h passwd.h record.h				\
		upgrade.h error.h keydb.h listform.h prefs.h		\
		resource.h util.h crypto.h keyedit.h			\
		memutil.h pwhash.h uiutil.h snib.h pack.h unpack.h	\
		reencrypt.h sort.h secrand.h prototype.h

OBJ		= $(subst .c,.o,$(SRC))
BIN             = $(APP).bin
DEF		= $(APP).def
EXE		= $(APP)

EN_PRC          = $(BASE)-en.prc

CC              = m68k-palmos-gcc
PILRC           = pilrc
TXT2BITM        = txt2bitm
BUILDPRC        = build-prc
AWK		= awk

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
		-Wstrict-prototypes -Wmissing-prototypes -Winline		\
		-Wlarger-than-260 -Wshadow -Wcast-align	
# 		-Wsign-compare
OPTIM		= -O3 -finline-functions -g
LIBS            = -lPalmOSGlue
CFLAGS		= $(OPTIM) $(WARN) $(DEFINES) $(INCLUDES)

HELP_TXT        = $(wildcard help/*/*.txt)

DOCS		= HACKING TODO TESTS 

SRC_DIST        = $(RCP_IN) Makefile $(RESOURCES) \
		  $(DOCS) $(SRC) $(HEADERS) $(DEF) \
		  $(HELP_TXT)

TOP_DIST	= $(PRCS) COPYING README INSTALL

DIST_BALL	= $(APP)-$(VERSION).tar.gz
DIST_ZIP	= $(APP)-$(VERSION).zip
TAR		= tar
ZIP		= zip

SED_SUBST        = -e "s/__VERSION__/$(VERSION)/g" \
		   -e "s/__DATE__/$(BUILD_DATE)/g"

BASE		= $(APP)-$(VERSION)

# For a list of ISO language codes, see
# http://www.unicode.org/unicode/onlinedat/languages.html
LANGUAGES = en de fr es it ja no ny nl pt sv 

PRCS = $(foreach lang, $(LANGUAGES), $(BASE)-$(lang).prc)

default: $(BASE)-en.prc

all: $(PRCS) 

$(BASE)-%.prc: %.resstamp $(EXE)
	$(BUILDPRC) $@ 'Keyring' Gtkr $(EXE) res/$*/*.bin
	@ls -l $@

%.resstamp: $(BITMAPS) resource.h 
%.resstamp: $(RCP)
	@[ -d res/$* ] || mkdir -p res/$*
	@-rm -f res/$*/*
	@-rm -f *.bin
	$(PILRC) -allowEditID -H auto.h.tmp -q $(shell [ "$*" = ja ] && echo -Fj) -L $* $(RCP) res/$*/ >/dev/null
	@if cmp -s auto.h auto.h.tmp; then rm -f auto.h.tmp; \
	 else mv auto.h.tmp auto.h; fi
	@touch $@

dist: $(DIST_BALL) $(DIST_ZIP)

tmpdir:=$(shell echo _build.$$$$)
$(DIST_BALL) $(DIST_ZIP): $(SRC_DIST) $(TOP_DIST)
	rm -rf $(tmpdir)
	mkdir -p $(tmpdir)/$(BASE)/src
	cp --parents $(SRC_DIST) $(tmpdir)/$(BASE)/src
	cp $(TOP_DIST) $(tmpdir)/$(BASE)
	$(TAR) -C $(tmpdir) -czf $(DIST_BALL) $(BASE)
	cd $(tmpdir) && $(ZIP) -rq9 ../$(DIST_ZIP) $(BASE)
	@ls -l $(DIST_BALL) $(DIST_ZIP)
	rm -fr $(tmpdir)

# I hate accidentally editing the generated file, so the chmod 
# tries to discourage it
$(RCP): $(RCP_IN) Makefile $(RESOURCES)
	@rm -f $@
	(echo '// ******DYNAMICALLY GENERATED DO NOT EDIT********'; \
	 sed $(SED_SUBST) $(RCP_IN)) > $@
	@chmod -w $@

$(EXE):       $(SRC:.c=.o) ;
	$(CC) $(CFLAGS) $^ $(LIBS) -o $(EXE)

# We try to avoid touching auto.h, because that will kick off
# rebuilding a lot of source and it's often not necessary.
auto.h: en.resstamp

%.s: %.c
	$(CC) $(CFLAGS) -S $< 

%.o: %.c auto.h prototype.h
	$(CC) $(CFLAGS) -c $< -o $*.o

clean:
	rm -f *.o *.d $(EXE) $(RCP) *.bin res/*/* *.grc *.prc *.resstamp \
	prototype.h *.bin *.d .*.stamp auto.h
	rmdir res/*

tags: TAGS
TAGS: *.c *.h
	etags *.c *.h

# for the GNU id-tools package: 
ID: .
	mkid

.PHONY: install proto

install: $(EN_PRC)
	pilot-xfer -i $(EN_PRC)


MKPROTO_C = $(SRC)

prototype.h: proto
proto: .proto.stamp

.proto.stamp: script/mkproto.awk $(MKPROTO_C)
	$(AWK) -f script/mkproto.awk $(MKPROTO_C) \
		>prototype.h.new
	@if test -f prototype.h && cmp -s prototype.h.new prototype.h; \
	then rm -f prototype.h.new; \
	echo No changes to prototypes; \
	else \
	echo Installing new prototype.h; \
	mv prototype.h.new prototype.h; \
	fi
	@touch $@


$(OBJ): $(HEADERS)

