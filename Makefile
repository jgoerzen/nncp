REDO ?= contrib/do -c

warning:
	@echo WARNING: this is not real Makefile. Just proxying commands to redo command

all: warning
	$(REDO) $@

clean: warning
	$(REDO) $@

install: warning
	$(REDO) $@

install-strip: warning
	$(REDO) $@

uninstall: warning
	$(REDO) $@
