CC=g++
CFLAGS=-std=c++17 -Wall -pedantic
LD=-lpcap
SRC=*.cpp
PROJ=sslsniff
LOGIN=xsovam00
.PHONY:$(PROJ)
$(PROJ):
	$(CC) $(CFLAGS) $(SRC) $(LD) -o $(PROJ)
pack:
	tar cf $(LOGIN).tar --ignore-failed-read Makefile *.cpp *.h sslsniff.1 *.pdf
