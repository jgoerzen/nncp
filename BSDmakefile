VERSION != cat VERSION
GO ?= go

GO_MOD_EXISTS != $(GO) help mod >/dev/null 2>&1 || echo no

.if ${GO_MOD_EXISTS} == "no"
BUILDMOD ?=
GOPATH ?= $(PWD)
.else
BUILDMOD ?= -mod=vendor
GOPATH ?= $(PWD)/gopath
.endif

include common.mk
