CC=g++
LD=-lpcap
SRC=*.cpp
PROJ=sslsniff
LOGIN=xsovam00
.PHONY:$(PROJ)
$(PROJ):
	$(CC) $(SRC) $(LD) -o $(PROJ)
pack:
	tar cf $(LOGIN).tar Makefile *.cpp *.h *.md *.pdf
