# define LATTE_FLAGS and pages

latte_pages=$(addsuffix .latte, $(pages))
html_pages=$(addsuffix .html, $(pages))

latte_all: $(html_pages)

.PHONY: latte_clean clean all latte_all
latte_clean:
	rm -f $(html_pages)

clean: latte_clean

%.html: %.latte $(latte_libs)
	latte-html $(addprefix -l, $(latte_libs)) $(LATTE_FLAGS) -o $@ $<

upload_files += $(html_pages)


