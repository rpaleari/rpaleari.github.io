TMPDIR=/dev/shm

# Sass-related variables
SASS_TMPCACHE=$(TMPDIR)/sass-cache
SASS_CACHE=.sass-cache

# Jekyll autogenerated files
JEKYLL_GEN_PUB=_data/pubs.json

all: serve
.phony: all serve drafts clean dist-clean

# These two rules are to move the Sass cache to $TMPDIR, by sym-linking
# .sass-cache to $TMPDIR/sass-cache/
$(SASS_TMPCACHE):
	mkdir $(SASS_TMPCACHE)

$(SASS_CACHE): $(SASS_TMPCACHE)
	ln -s $(SASS_TMPCACHE) $(SASS_CACHE)

$(JEKYLL_GEN_PUB): _utils/pubs/pubs.bib
	python _utils/pubs/bibtex.py $^ >$@

serve: $(SASS_CACHE) $(JEKYLL_GEN_PUB)
	jekyll serve

drafts: $(SASS_CACHE) $(JEKYLL_GEN_PUB)
	jekyll serve --drafts --future

clean:
	-rm -fr $(SASS_CACHE)
	-rm -fr $(SASS_TMPCACHE)
	jekyll clean

dist-clean: clean
	-rm $(JEKYLL_GEN_PUB)
