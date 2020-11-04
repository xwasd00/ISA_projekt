CC=g++
CFLAGS=-std=c++17 -Wall -Wextra -pedantic
LD=-lpcap
SRC=*.cpp
PROJ=sslsniff
LOGIN=xsovam00
.PHONY:$(PROJ)
$(PROJ):
	$(CC) $(CFLAGS) $(SRC) $(LD) -o $(PROJ)
pack:
	tar cf $(LOGIN).tar Makefile *.cpp *.h *.md *.pdf
