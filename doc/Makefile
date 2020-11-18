NAME=manual
ARCHIVE=xsovam00-fit
DEPS=*.tex

.PHONY: $(NAME).pdf
$(NAME).pdf: $(NAME).ps
	ps2pdf -sPAPERSIZE=a4 $(NAME).ps
$(NAME).ps: $(NAME).dvi
	dvips -t a4 $(NAME).dvi
$(NAME).dvi: $(NAME).tex
	latex $(NAME).tex
	latex $(NAME).tex
clean-all: clean
	rm -f $(NAME).pdf $(ARCHIVE).zip
clear: clean
clean:
	rm -f *.aux *.dvi *.log *.out *.ps *.tex~
merlin: pack
	scp $(ARCHIVE).zip merlin:~/Dokumenty/ity/$(NAME)/
pack:
	zip $(ARCHIVE).zip Makefile $(DEPS)
run: $(NAME).pdf
	evince $(NAME).pdf
