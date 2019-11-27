all: nncp.info nncp.html

MAKEINFO ?= makeinfo

sp.utxt: sp.txt
	plantuml -tutxt sp.txt

nncp.info: *.texi sp.utxt pedro.txt
	$(MAKEINFO) -o nncp.info index.texi

CSS != cat style.css

nncp.html: *.texi sp.utxt pedro.txt
	rm -f nncp.html/*.html
	$(MAKEINFO) --html \
		--set-customization-variable EXTRA_HEAD='<link rev="made" href="mailto:stargrave+webmaster@nncpgo.org">' \
		--set-customization-variable CSS_LINES='$(CSS)' \
		--set-customization-variable SHOW_TITLE=0 \
		--set-customization-variable USE_ACCESSKEY=0 \
		--set-customization-variable DATE_IN_HEADER=1 \
		--set-customization-variable TOP_NODE_UP_URL=index.html \
		--set-customization-variable CLOSE_QUOTE_SYMBOL=\" \
		--set-customization-variable OPEN_QUOTE_SYMBOL=\" \
		-o nncp.html index.texi
	cp -r .well-known nncp.html/
