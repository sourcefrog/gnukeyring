# Makefile for the GNU Keyring site
# $Id$


pages=index screenshots download mirrors thanks plans faq	\
      history conduits lists contribute

extra=robots.txt Blatant-Plug-Insert-4-Cheap-Dark.jpg snaps/*.png icons/*.gif
# cvs_logs=$(addsuffix -log.txt, $(pages))
site_files=$(html_pages) $(extra)

sites=linuxcare.com.au:/var/www/projects/gnukeyring \
	gnukeyring.sourceforge.net:/home/groups/gnukeyring/htdocs

latte_libs=style.latte

all: latte_all

upload: $(site_files)
	for i in $(sites); do rsync --relative -l -v --times -z -e ssh $(site_files) $$i; done

%-log.txt: %.latte
	cvs log $< >$@

include latte.mk