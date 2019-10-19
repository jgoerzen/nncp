VERSION = $(shell cat VERSION)
GO ?= go

GO_MOD_EXISTS = $(shell $(GO) help mod >/dev/null 2>&1 || echo no)

ifeq ($(GO_MOD_EXISTS), no)
BUILDMOD ?=
GOPATH ?= $(PWD)
else
BUILDMOD ?= -mod=vendor
GOPATH ?= $(PWD)/gopath
endif

include common.mk
