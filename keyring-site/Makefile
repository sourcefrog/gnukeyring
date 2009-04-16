# Makefile for the Keyring for PalmOS site
# $Header$

pages=index guide download thanks plans faq crypto	\
      history conduits lists contribute building prerelease

extra=robots.txt style.css snaps/*.png myicons/*.gif

htp_libs=htp.def keyring.htt

htp_pages=$(addsuffix .htp, $(pages))
html_pages=$(addsuffix .html, $(pages))

site_files=$(html_pages) $(extra)

all:

.PHONY: htp_clean htp_all
htp_clean:
	rm -f $(html_pages)

%.html: %.htp $(htp_libs)
	htp -quiet -nodepend $< $@


$(site_files): $(htp_libs)

sites=hoenicke,gnukeyring@web.sourceforge.net:htdocs

all: $(html_pages)

upload: $(site_files)
	for i in $(sites); do \
	rsync --rsh="ssh" --relative --links -v --ignore-times -z $(site_files) $$i; done

%-log.txt: %.latte
	cvs log $< >$@
