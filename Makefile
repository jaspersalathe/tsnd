
default: all

all: Debug Release

Debug:
	$(MAKE) --makefile Makefile.Debug

Release:
	$(MAKE) --makefile Makefile.Release

clean:
	$(MAKE) --makefile Makefile.Release clean
	$(MAKE) --makefile Makefile.Debug clean

.PHONY: default all Debug Release clean