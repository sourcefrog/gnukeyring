# Makefile for the GNU Keyring site
# $Id$


pages=index license screenshots download mirrors thanks plans faq history

latte_pages=$(addsuffix .latte, $(pages))
html_pages=$(addsuffix .html, $(pages))
extra=robots.txt Blatant-Plug-Insert-4-Cheap-Dark.jpg snaps/*.png

sites=linuxcare.com.au:/var/www/projects/gnukeyring \
	gnukeyring.sourceforge.net:/home/groups/gnukeyring/htdocs

all: $(html_pages)

%.html: %.latte style.latte
	latte-html $(LATTE_FLAGS) -lstyle.latte -o $@ $< 

upload: $(html_pages) $(extra)
	for i in $(sites); do rsync --relative -l -v --times -z -e ssh $(html_pages) $(extra) $$i; done
