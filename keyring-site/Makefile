# Makefile for the Keyring for PalmOS site
# $Header$

pages=index screenshots download thanks plans faq	\
      history conduits lists contribute building

extra=robots.txt style.css snaps/*.png icons/*.gif
# cvs_logs=$(addsuffix -log.txt, $(pages))

include latte.mk

site_files=$(html_pages) $(extra)

$(site_files): style.latte

sites=gnukeyring.sourceforge.net:/home/groups/g/gn/gnukeyring/htdocs

latte_libs=style.latte

all: latte_all

upload: $(site_files)
	for i in $(sites); do \
	rsync --relative -l -v --times --ignore-times -z -e ssh $(site_files) $$i; done

%-log.txt: %.latte
	cvs log $< >$@
