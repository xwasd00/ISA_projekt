#ifndef ISA_ARGS_H
#define ISA_ARGS_H
#include <getopt.h>
#include <iostream>
#include <pcap.h>
/**
 *  @brief třída pro zpracování argumentů k projektu do ISA
 *  @author Michal Sova (xsovam00)
 *
 *  Využití funkce getopt_long inspirováno příkladem:https://codeyarns.com/2015/01/30/how-to-parse-program-options-in-c-using-getopt_long/
 */
class Args {


public:


	bool file = false; /**< zachytávání proběhne ze souboru nebo na síťovém rozhraní */

	std::string dev; /**< název rozhraní, na kterém se budou pakety zachytávat */

	std::string filename; /**< soubor se síťovým provozem */

    /**
 * @brief funkce pro získání argumentů a upravení chování programu
 * @param argc počet argumentů
 * @param argv pole argumentů
 * @returns 0 pokud proběhne parsování bez problému
 * @returns -1 v případě vypsání rozhraní nebo nápovědy
 * @returns 50 jinak
 * */
	int getOpts(int, char**);

    /**
 * @brief vypsání možných rozhraní
 * */
	void printDevs();

    /**
 * @brief funkce pro vypsání nápovědy
 * */
	void printHelp();
};


#endif //ISA_ARGS_H
