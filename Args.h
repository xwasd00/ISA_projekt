#ifndef ISA_ARGS_H
#define ISA_ARGS_H
#include <getopt.h>
#include <iostream>
#include <pcap.h>

// třída pro zpracování argumentů k projektu do ISA
// Michal Sova (xsovam00)
// Využití funkce getopt_long inspirováno příkladem:https://codeyarns.com/2015/01/30/how-to-parse-program-options-in-c-using-getopt_long/

class Args {


public:

	// TODO: comment
	bool file = false;
	// název rozhraní, na kterém se budou pakety zachytávat
	std::string dev;
	// soubor se síťovým provozem
	std::string filename;

	// funkce pro získání argumentů a upravení chování programu
	// v případě vypsání rozhraní vrací funkce -1
	// pokud proběhne parsování bez problému, vrací funkce 0
	// jinak 1
	int getOpts(int, char**);

	// vytisknutí možných rozhraní
	void printDevs();
	
	// funkce pro vypsání nápovědy
	void printHelp();
};


#endif //ISA_ARGS_H
