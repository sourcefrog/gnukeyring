# Keyring for PalmOS.  
# 
# Resource file to be preprocessed.
#
# Copyright (C) 1999, 2000, 2001 by Martin Pool <mbp@users.sourceforge.net>
# Copyright (C) 2002-2005 by Jochen Hoenicke <hoenicke@users.sourceforge.net>
#
# $Id$

# Note: 
# Turning on debugger support (-g) costs about 140 bytes
# -mdebug-labels costs about 3100 bytes

# Turning on  -finline-functions costs about 532 bytes
# Empirically the smallest executables come from -O2, which makes sense
# because it is defined to be the greatest amount of optimization that
# does not involve size-speed tradeoffs.

# Adding -O3 seems to make a difference to execution time as many
# functions are inlined.  However, it also generates code that
# grievously confuses gdb.  So, for debugging we turn optimization 
# off altogether and for ship versions we turn it right up.

# TODO: Switch optimization based on version number?

# On the other hand -O0 seems to make gcc not treat constants
# properly. Foo. 

APP             = keyring
BUILD_DATE     := $(shell date +'%Y-%m-%d')
VERSION         = 2.0-pre6
DEFINES		= -DBETA -DkAppVersion=0x1996
WARN	        = -Wall -Winline -Wunused -W	\
		-Wstrict-prototypes -Wmissing-prototypes \
		-Wlarger-than-384 -Wshadow -Wcast-align

OPTIM		= -O2 -g -mdebug-labels
INCLUDES        = -IpilotSSLeay/include -I$(HOME)/palmdev/palmOne
LIBS            = -lPalmOSGlue
CFLAGS		= $(OPTIM) $(WARN) $(DEFINES) $(INCLUDES)

RCP             = $(APP).rcp
RCP_IN          = $(RCP).ja $(RCP).iso2 $(RCP).cp1251 $(RCP).in
BITMAPS         = keyring-15-1.pbm keyring-15-8.ppm \
		  keyring-22-1.pbm keyring-22-8.ppm \
		  keyring-64-8.ppm keyring-22.xcf keyring-64.xcf \
                  lock-1.pbm lock-8.ppm lock-hi-8.ppm \
                  unlock-1.pbm unlock-8.ppm unlock-hi-8.ppm
WIDEBITMAPS     = keyring-32-1.pbm keyring-32-8.ppm
RESOURCES	= fontPW.txt fontstar.txt $(BITMAPS)
SRC             = keyring.c keyedit.c keydb.c memutil.c listform.c	\
		  crypto.c passwd.c uiutil.c generate.c prefs.c		\
		  export.c record.c category.c				\
		  setpasswd.c pwhash.c snib.c reencrypt.c sort.c	\
		  secrand.c search.c pronounce.c sha1.c			\
		  upgrade.c # md5.c

ASMGEN          = sha1-m68k.pl # md5-m68k.pl

GLIBDEF         = ssl-des.def ssl-md.def

HEADERS	        = sections.h sha1.h keyring.h record.h error.h    \
		  resource.h crypto.h pwhash.h snib.h includes.h  \
		  pronounce.h AESLib-noinline.h AESLib-inline.h # md5.h

OBJ		= $(subst .c,.o,$(SRC)) $(subst .def,-stubs.o,$(GLIBDEF)) \
		  $(subst .pl,.o,$(ASMGEN)) \
		  $(APP)-sections.o 
BIN             = $(APP).bin
DEF		= $(APP).def $(GLIBDEF)
EXE		= $(APP)

EN_PRC          = $(BASE)-en.prc

CC              = m68k-palmos-gcc
STUBGEN         = m68k-palmos-stubgen
MULTIGEN        = m68k-palmos-multigen
OBJCOPY         = m68k-palmos-objcopy
PILRC           = pilrc
TXT2BITM        = txt2bitm
BUILDPRC        = build-prc
AWK		= awk
PERL		= perl
JAVA		= java

HELP_TXT        = $(wildcard help/*/*.txt)
AESLIBS         = AESLib-SDK/PRC/AESLib.prc
SSLEAYLIBS      = $(wildcard pilotSSLeay/shlib/*.prc)
SSLEAYINCS      = $(wildcard pilotSSLeay/include/*.h)
SSLEAY          = $(SSLEAYINCS) $(SSLEAYLIBS)
SCRIPTS         = script/mkproto.pl

DOCS		= HACKING TODO TESTS doc/fips181.txt \
		  doc/rfc-2104.txt doc/rfc-2898.txt doc/rfc-3174.txt

SRC_DIST        = $(RCP_IN) Makefile $(RESOURCES) \
		  $(DOCS) $(SRC) $(ASMGEN) $(HEADERS) $(DEF) \
		  $(subst .def,-stubs.c,$(GLIBDEF)) \
		  $(HELP_TXT) $(SCRIPTS) prondata.c \
		  $(SSLEAY) $(AESLIBS) \
		  prototype.h .proto.stamp $(subst .pl,.o,$(ASMGEN)) \
		  $(WIDEBITMAPS)

TOP_DIST	= COPYING COPYING.AESLib README INSTALL NEWS

BASE		= $(APP)-$(VERSION)
DIST_BALL	= $(BASE).tar.gz
DIST_ZIP	= $(BASE).zip
DIST_NEWS	= $(BASE).news
DIST_SIGS	= $(BASE).sig.zip
TAR		= tar
ZIP		= zip

SED_SUBST        = -e "s/__VERSION__/$(VERSION)/g" \
		   -e "s/__DATE__/$(BUILD_DATE)/g"

DEFAULTLANG     = de

# For a list of ISO language codes, see
# http://www.loc.gov/standards/iso639-2/englangn.html
# The codes nn and nb for nynorsk and bokmål are recent additions.
LANGUAGES = en ca cs da de es fi fr hu it ja nl nb nn pl pt sv ru

LOCALES = enUS <en caES <ca csCZ <cs daDK <da deDE <de esES <es fiFI <fi \
          frFR <fr huHU <hu itIT <it jaJP <ja nlNL <nl noNO <nb plPL <pl \
          ptBR <pt svSE <sv ruRU <ru

PILRCOPTS_ja = -Fj
PILRCOPTS_ru = -Fc

PRCS = $(foreach lang, $(LANGUAGES), $(BASE)-$(lang).prc)
DIST_BIN = $(foreach lang, $(LANGUAGES), $(BASE)-$(lang).zip)
RESSTAMPS = $(foreach lang, $(LANGUAGES), $(lang).resstamp)
DIST_BIN_SIG = $(patsubst %,%.sig,$(DIST_BIN) $(PRCS))
DIST_BALL_SIG = $(patsubst %,%.sig,$(DIST_BALL))
SSLEAYLIBS_SIG = $(patsubst %,%.sig,$(SSLEAYLIBS))
AESLIBS_SIG = $(patsubst %,%.sig,$(AESLIBS))
SIGS = $(DIST_BIN_SIG) $(DIST_BALL_SIG) $(SSLEAYLIBS_SIG) $(AESLIBS_SIG)

default: $(BASE)-$(DEFAULTLANG).prc

all: $(PRCS) 

$(PRCS): $(BASE)-%.prc: $(EXE) %.resstamp
	cd res/$*; $(BUILDPRC) -o ../../$@ ../../$(APP).def ../../$(EXE) *.bin

$(RESSTAMPS): %.resstamp: $(BITMAPS) resource.h $(RCP) prondata.o $(WIDEBITMAPS)
	@[ -d res/$* ] || mkdir -p res/$*
	@-rm -f res/$*/*
	@-rm -f *.bin
	$(PILRC) -allowEditID -q $(PILRCOPTS_$*) -L $* $(RCP) res/$*/ >/dev/null
	$(OBJCOPY) -Obinary prondata.o res/$*/PRON03e8.bin
	@touch $@

# Convert keyring icons to 32 pixel width, so it is easier to center them
# in the about box.
# Due to a bug in convert, we have to do it in two steps.
$(WIDEBITMAPS): keyring-32-%: keyring-22-%
	convert -border 6x1 -bordercolor white $< tmp$*
	convert -shave 1x1 tmp$* $@
	@rm tmp$*

dist: $(DIST_BALL) $(DIST_BIN) $(DIST_NEWS)

tmpdir:=$(shell echo _build.$$$$)
$(DIST_BALL): $(SRC_DIST) $(TOP_DIST)
	rm -rf $(tmpdir)
	mkdir -p $(tmpdir)/$(BASE)
	cp -p --parents $(SRC_DIST) $(tmpdir)/$(BASE)
	cp $(TOP_DIST) $(tmpdir)/$(BASE)
	$(TAR) -C $(tmpdir) -czf $(DIST_BALL) $(BASE)
	rm -fr $(tmpdir)

$(BASE)-%.zip: $(TOP_DIST) $(BASE)-%.prc $(SSLEAYLIBS) $(AESLIBS) \
	$(BASE)-%.prc.sig $(SSLEAYLIBS_SIG) $(AESLIBS_SIG)
	$(ZIP) -jq9 $@ $^

$(DIST_NEWS): NEWS $(DIST_BIN) $(DIST_BALL)
	(cat NEWS ; md5sum $(PRCS) $(DIST_BALL) $(SSLEAYLIBS) $(AESLIBS);echo ) > NEWS.tmp
	gpg --clearsign -o $(DIST_NEWS) NEWS.tmp
	rm -f NEWS.tmp
	@ls -l $(DIST_BIN) $(DIST_BALL)

$(DIST_SIGS): $(SIGS)
	$(ZIP) -jq9 $@ $^

$(SIGS): %.sig: %
	rm -f $@
	gpg --detach-sign $*

# I hate accidentally editing the generated file, so the chmod 
# tries to discourage it
$(RCP): $(RCP_IN) Makefile $(RESOURCES)
	@rm -f $@
	(echo '// ******DYNAMICALLY GENERATED DO NOT EDIT********'; \
	 sed $(SED_SUBST) $(RCP_IN)) > $@
	@chmod -w $@

$(APP)-sections.o $(APP)-sections.ld: $(APP).def
	$(MULTIGEN) $(APP).def
	$(CC) -c $(APP)-sections.s

$(EXE): $(OBJ) $(APP)-sections.ld ;
	@echo $(CC) $(OPTIM) $^ $(LIBS) -o $(EXE)
	@$(CC) $(CFLAGS) $^ $(LIBS) -o $(EXE)

# Rules for building overlays
#
# XXX The java program to build the overlays is still under construction
# mail me (hoenicke at users.sf.net) if you're interested in the source.
#
$(DIST_ZIP): $(PRCS) $(SSLEAYLIBS) $(AESLIBS)
	@[ -d ovl ] || mkdir ovl
	CLASSPATH=script/astroinfo-pdb.jar $(JAVA) \
	net.sf.astroinfo.pdb.CreateOverlay ovl/$(BASE) \
	$(LOCALES:<%=$(BASE)-%.prc)
	$(ZIP) -jq9 $(DIST_ZIP) ovl/* $(SSLEAYLIBS) $(AESLIBS)

%-stubs.c: %.def
	$(STUBGEN) $<

%.o: %.pl
	$(PERL) $< > $*.s
	$(CC) -c $*.s -o $@
	@rm $*.s

%.s: %.c
	$(CC) $(CFLAGS) -S $< 

$(OBJ): $(HEADERS) prototype.h
%.o: %.c
	@echo $(CC) $(OPTIM) -c $< -o $*.o
	@$(CC) $(CFLAGS) -c $< -o $*.o

clean:
	rm -f *.o *.d $(EXE) $(RCP) TAGS *.bin *.grc *.prc *.resstamp \
	prototype.h *.bin *.d .*.stamp *~ *.tmp
	rm -rf res

scrub:	clean
	rm -f $(APP)-*.tar.gz $(APP)-*.zip $(APP)-*.news

tags: TAGS
TAGS: *.c *.h
	etags *.c *.h

# for the GNU id-tools package: 
ID: .
	mkid

.PHONY: install proto

install: install-en

install-%: $(BASE)-%.prc
	pilot-xfer -i $^


MKPROTO_C = $(SRC)

proto: prototype.h
prototype.h: .proto.stamp; @true

.proto.stamp: script/mkproto.pl $(MKPROTO_C)
	$(PERL) script/mkproto.pl $(MKPROTO_C) > prototype.h.new
	@if test -f prototype.h && cmp -s prototype.h.new prototype.h; \
	then rm -f prototype.h.new; \
	echo No changes to prototype.h; \
	else \
	echo Installing new prototype.h; \
	mv prototype.h.new prototype.h; \
	fi
	@touch $@
