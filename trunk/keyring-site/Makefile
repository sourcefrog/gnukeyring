# Makefile for the GNU Keyring site
# $Id$


pages=index screenshots download mirrors thanks plans faq	\
      history conduits lists contribute

latte_pages=$(addsuffix .latte, $(pages))
html_pages=$(addsuffix .html, $(pages))
extra=robots.txt Blatant-Plug-Insert-4-Cheap-Dark.jpg snaps/*.png icons/*.gif
# cvs_logs=$(addsuffix -log.txt, $(pages))
site_files=$(html_pages) $(extra)

sites=linuxcare.com.au:/var/www/projects/gnukeyring \
	gnukeyring.sourceforge.net:/home/groups/gnukeyring/htdocs

all: $(html_pages)

%.html: %.latte style.latte
	latte-html $(LATTE_FLAGS) -lstyle.latte -o $@ $< 

upload: $(site_files)
	for i in $(sites); do rsync --relative -l -v --times -z -e ssh $(site_files) $$i; done

%-log.txt: %.latte
	cvs log $< >$@
