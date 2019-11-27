GOPATH != pwd
VERSION != cat VERSION

GO ?= go
PREFIX ?= /usr/local

SENDMAIL ?= /usr/sbin/sendmail
CFGPATH ?= $(PREFIX)/etc/nncp.hjson
SPOOLPATH ?= /var/spool/nncp
LOGPATH ?= /var/spool/nncp/log

BINDIR = $(DESTDIR)$(PREFIX)/bin
INFODIR = $(DESTDIR)$(PREFIX)/info
DOCDIR = $(DESTDIR)$(PREFIX)/share/doc/nncp

MOD = go.cypherpunks.ru/nncp/v5

LDFLAGS = \
	-X $(MOD).Version=$(VERSION) \
	-X $(MOD).DefaultCfgPath=$(CFGPATH) \
	-X $(MOD).DefaultSendmailPath=$(SENDMAIL) \
	-X $(MOD).DefaultSpoolPath=$(SPOOLPATH) \
	-X $(MOD).DefaultLogPath=$(LOGPATH)

ALL = \
	$(BIN)/nncp-bundle \
	$(BIN)/nncp-call \
	$(BIN)/nncp-caller \
	$(BIN)/nncp-cfgenc \
	$(BIN)/nncp-cfgmin \
	$(BIN)/nncp-cfgnew \
	$(BIN)/nncp-check \
	$(BIN)/nncp-daemon \
	$(BIN)/nncp-exec \
	$(BIN)/nncp-file \
	$(BIN)/nncp-freq \
	$(BIN)/nncp-log \
	$(BIN)/nncp-pkt \
	$(BIN)/nncp-reass \
	$(BIN)/nncp-rm \
	$(BIN)/nncp-stat \
	$(BIN)/nncp-toss \
	$(BIN)/nncp-xfer

SRC := $(PWD)/src
BIN := $(PWD)/bin

all: $(ALL)

$(ALL):
	mkdir -p $(BIN)
	cd $(SRC) ; GOPATH=$(GOPATH) $(GO) build \
		-o $(BIN)/$$(basename $@) \
		-ldflags "$(LDFLAGS)" \
		$(MOD)/cmd/$$(basename $@)

test:
	cd $(SRC) ; GOPATH=$(GOPATH) $(GO) test -failfast $(MOD)/...

clean:
	rm -rf $(BIN)

.PHONY: doc

doc:
	$(MAKE) -C doc

install: all doc
	mkdir -p $(BINDIR)
	cp -f $(ALL) $(BINDIR)
	for e in $(ALL) ; do chmod 755 $(BINDIR)/$$(basename $$e) ; done
	mkdir -p $(INFODIR)
	cp -f doc/nncp.info $(INFODIR)
	chmod 644 $(INFODIR)/nncp.info
	mkdir -p $(DOCDIR)
	cp -f -L AUTHORS NEWS NEWS.RU README README.RU THANKS $(DOCDIR)
	chmod 644 $(DOCDIR)/*

install-strip: install
	for e in $(ALL) ; do strip $(BINDIR)/$$(basename $$e) ; done
