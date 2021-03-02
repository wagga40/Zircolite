#!/usr/bin/env make

define HELP_MENU
	Usage: make [<env>] <target> [<target> ...]

	Main targets:
		all (default)   call the default target(s)
		clean           remove all default artifacts
		help            show this help

	Refer to the documentation for use cases and examples.
endef

.PHONY: all clean help

all: clean

help:
	$(info $(HELP_MENU))

clean:
	rm -rf "detected_events.json"
	rm -rf ./tmp-*
	rm -f zircolite.log
	rm -f fields.json

