# Keyring for PalmOS.  
# 
# Resource file to be preprocessed.
#
# Copyright (C) 1999, 2000, 2001 by Martin Pool <mbp@users.sourceforge.net>
# Copyright (C) 2002-2003 by Jochen Hoenicke <hoenicke@users.sourceforge.net>
#
# $Header$

APP             = keyring
ICONTEXT        = "Keyring"
APPID           = "Gtkr"

# XXX: You may have to edit this to match your SDK installation
#PALM_BASE       = /usr/local/include/palmos3.5
#C_INCLUDE_PATH  = $(PALM_BASE):$(PALM_BASE)/Core:$(PALM_BASE)/Core/Hardware:$(PALM_BASE)/Core/System:$(PALM_BASE)/Core/UI:$(PALM_BASE)/Libraries/PalmOSGlue:$(PALM_BASE)/Dynamic:$(PALM_BASE)/Libraries
#export C_INCLUDE_PATH

RCP             = $(APP).rcp
RCP_IN          = $(RCP).ja $(RCP).iso2 $(RCP).in
BITMAPS         = keyring-15-1.pbm keyring-32-1.ppm keyring-32-8.ppm    \
		  keyring-64-8.ppm keyring-22.xcf lock.xbm unlock.xbm
RESOURCES	= fontPW.txt fontstar.txt $(BITMAPS)
SRC             = keyring.c keyedit.c keydb.c memutil.c listform.c	\
		  crypto.c passwd.c uiutil.c generate.c prefs.c		\
		  export.c dbutil.c upgrade.c record.c category.c	\
		  setpasswd.c pwhash.c snib.c reencrypt.c pack.c	\
		  unpack.c sort.c secrand.c search.c pronounce.c

GLIBDEF         = ssl-md.def ssl-des.def

HEADERS	        = keyring.h record.h error.h \
		  resource.h crypto.h pwhash.h snib.h includes.h        \
		  pronounce.h

OBJ		= $(subst .c,.o,$(SRC)) $(subst .def,-stubs.o,$(GLIBDEF))
BIN             = $(APP).bin
DEF		= $(APP).def $(GLIBDEF)
EXE		= $(APP)

EN_PRC          = $(BASE)-en.prc

CC              = m68k-palmos-gcc
STUBGEN         = m68k-palmos-stubgen
PILRC           = pilrc
TXT2BITM        = txt2bitm
BUILDPRC        = build-prc
AWK		= awk
PERL		= perl
JAVA		= java

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

BUILD_DATE     := $(shell date +'%Y-%m-%d')
VERSION         = 1.2.3
DEFINES		= -DkAppVersion=0x1023
WARN	        = -Wall -Winline -Wunused -W	\
		-Wstrict-prototypes -Wmissing-prototypes \
		-Wlarger-than-260 -Wshadow -Wcast-align

OPTIM		= -O2 #-g -mdebug-labels
INCLUDES        = -IpilotSSLeay/include
LIBS            = -lPalmOSGlue
CFLAGS		= $(OPTIM) $(WARN) $(DEFINES) $(INCLUDES)

HELP_TXT        = $(wildcard help/*/*.txt)
SSLEAYLIBS      = $(wildcard pilotSSLeay/shlib/*.prc)
SSLEAYINCS      = $(wildcard pilotSSLeay/include/*.h)
SSLEAY          = $(SSLEAYINCS) $(SSLEAYLIBS)
SCRIPTS         = script/mkproto.pl

DOCS		= HACKING TODO TESTS 

SRC_DIST        = $(RCP_IN) Makefile $(RESOURCES) \
		  $(DOCS) $(SRC) $(HEADERS) $(DEF) \
		  $(subst .def,-stubs.c,$(GLIBDEF)) \
		  $(HELP_TXT) $(SCRIPTS) $(SSLEAY)

TOP_DIST	= COPYING README INSTALL NEWS

BASE		= $(APP)-$(VERSION)
DIST_BALL	= $(BASE).tar.gz
DIST_ZIP	= $(BASE).zip
DIST_NEWS	= $(BASE).news
DIST_SIGS	= $(BASE).sig.zip
TAR		= tar
ZIP		= zip

SED_SUBST        = -e "s/__VERSION__/$(VERSION)/g" \
		   -e "s/__DATE__/$(BUILD_DATE)/g"


# For a list of ISO language codes, see
# http://www.loc.gov/standards/iso639-2/englangn.html
# The codes nn and nb for nynorsk and bokmål are recent additions.
LANGUAGES = en ca da de es fr it ja nl nb nn pt sv pl

LOCALES = enUS <en daDK <da deDE <de esES <es frFR <fr itIT <it \
          jpJP <ja nlNL <nl noNO <nb ptBR <pt svSE <sv plPL <pl

PRCS = $(foreach lang, $(LANGUAGES), $(BASE)-$(lang).prc)
DIST_BIN = $(foreach lang, $(LANGUAGES), $(BASE)-$(lang).zip)
DIST_BIN_SIG = $(patsubst %,%.sig,$(DIST_BIN) $(PRCS))
DIST_BALL_SIG = $(patsubst %,%.sig,$(DIST_BALL))
SSLEAYLIBS_SIG = $(patsubst %,%.sig,$(SSLEAYLIBS))
SIGS = $(DIST_BIN_SIG) $(DIST_BALL_SIG) $(SSLEAYLIBS_SIG)




default: $(BASE)-en.prc

all: $(PRCS) 

$(BASE)-%.prc: %.resstamp $(EXE)
	cd res/$*; $(BUILDPRC) ../../$@ 'Keyring' Gtkr ../../$(EXE) *.bin

%.resstamp: $(BITMAPS) resource.h 
%.resstamp: $(RCP)
	@[ -d res/$* ] || mkdir -p res/$*
	@-rm -f res/$*/*
	@-rm -f *.bin
	$(PILRC) -allowEditID -H auto.h.tmp -q $(shell [ "$*" = ja ] && echo -Fj) -L $* $(RCP) res/$*/ >/dev/null
	@if cmp -s auto.h auto.h.tmp; then rm -f auto.h.tmp; \
	 else mv auto.h.tmp auto.h; fi
	@touch $@

dist: $(DIST_BALL) $(DIST_BIN) $(DIST_NEWS) $(DIST_SIGS)

tmpdir:=$(shell echo _build.$$$$)
$(DIST_BALL): $(SRC_DIST) $(TOP_DIST)
	rm -rf $(tmpdir)
	mkdir -p $(tmpdir)/$(BASE)
	cp --parents $(SRC_DIST) $(tmpdir)/$(BASE)
	cp $(TOP_DIST) $(tmpdir)/$(BASE)
	$(TAR) -C $(tmpdir) -czf $(DIST_BALL) $(BASE)
	rm -fr $(tmpdir)

$(BASE)-%.zip: $(TOP_DIST) $(BASE)-%.prc $(SSLEAYLIBS)
	$(ZIP) -jq9 $@ $^

$(DIST_NEWS): NEWS $(DIST_BIN) $(DIST_BALL)
	(cat NEWS ; md5sum $(PRCS) $(DIST_BALL) $(SSLEAYLIBS);echo ) > NEWS.tmp
	rm -f $(DIST_NEWS)
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

$(EXE): $(OBJ) ;
	$(CC) $(CFLAGS) $^ $(LIBS) -o $(EXE)

# Rules for building overlays
#
# XXX The java program to build the overlays is still under construction
# mail me (hoenicke at users.sf.net) if you're interested in the source.
#
$(DIST_OVL_ZIP): $(PRCS) $(SSLEAYLIBS)
	@[ -d ovl ] || mkdir ovl
	CLASSPATH=script/astroinfo-pdb.jar $(JAVA) \
	net.sf.astroinfo.pdb.CreateOverlay ovl/$(BASE) \
	$(LOCALES:<%=$(BASE)-%.prc)
	$(ZIP) -jq9 $(BASE).zip ovl/* $(SSLEAYLIBS)

# We try to avoid touching auto.h, because that will kick off
# rebuilding a lot of source and it's often not necessary.
auto.h: en.resstamp

%-stubs.c: %.def
	$(STUBGEN) $<

%.s: %.c
	$(CC) $(CFLAGS) -S $< 

$(OBJ): $(HEADERS) auto.h prototype.h
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $*.o

clean:
	rm -f *.o *.d $(EXE) $(RCP) TAGS *.bin *.grc *.prc *.resstamp \
	prototype.h *.bin *.d .*.stamp auto.h *~ *.tmp
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
