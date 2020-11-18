// třída pro zpracování argumentů k projektu do ISA
// Michal Sova (xsovam00)

#include "Args.h"
using namespace std;

/**
 * @brief funkce pro získání argumentů a upravení chování programu
 * @param argc počet argumentů
 * @param argv pole argumentů
 * @returns 0 pokud proběhne parsování bez problému
 * @returns -1 v případě vypsání rozhraní nebo nápovědy
 * @returns 50 jinak
 * */
int Args::getOpts(int argc, char** argv){
	
	// nejsou žádné argumenty -> vypsání možných rozhraní
	if(argc < 2){
		printHelp();
		return -1;
	}


	// Předloha z: https://codeyarns.com/2015/01/30/how-to-parse-program-options-in-c-using-getopt_long/

	// dlouhé možnosti
	const option longopts[] = {
		{"help", no_argument, nullptr, 'h'}};
	int option;

	// získání možností z getopt_long 
	while((option = getopt_long(argc, argv, ":i:r:h", longopts, nullptr)) != -1){
		switch(option){

			// ./sslsniff -i <interface>
			// kde <interfacce> je název rozhraní (např. eth0)
        	case 'i':
				dev = optarg;
				break;

			// ./sslsniff -r <file>
			// kde <file> je název souboru se síťovým provozem (*.pcapng)
			case 'r':
				filename = optarg;
				file = true;
				break;

			// ./sslsniff --help
			// vytisknutí nápovědy
			case 'h':
				printHelp();
				return -1;
				break;
			
			// chybí soubor v případě -r
			// v případě argumentu -i bez hodnoty vypíše názvy možných rozhraní
			case ':':
				if(optopt == 'i'){
					printDevs();
					return -1;
				}
				cerr << "Možnost -" << (char)optopt << " potřebuje hodnotu." << endl;
				return 50;
				break;

			// neznámé možnosti filtr ignoruje
			default:
				break;
		}
	}
	// konec využití předlohy


	//chybí soubor nebo nesprávný typ souboru
	if(file && filename.size() == 0){
		cerr << "Chybí soubor." << endl;
		return 50;
	}

	//není ani soubor ani rozhraní 
	if(!file && dev.size() == 0){
		cerr << "ani soubor ani rozhraní" << endl;
		printHelp();
		return -1;
	}

	return 0;
}

/**
 * @brief vypsání možných rozhraní
 * */
void Args::printDevs(){
	
	// v případě chyby se zde vypíše chybové hlášení
	char errbuff[PCAP_ERRBUF_SIZE];
	// seznam rozhraní
	pcap_if_t *alldevs;
	
	// najití rozhraní pomocí funkce pcap_findalldevs
	if (pcap_findalldevs(&alldevs, errbuff) != 0){
		cerr << "pcap_findalldevs error: " << errbuff << endl;
	}

	// vypsání rozhraní s krátkým popiskem (pokud je přítomen)
	pcap_if_t *dev = alldevs;
	while (dev != NULL){

		// jméno rozhraní
		cout << dev->name;

		// popis
		if(dev->description != NULL){
			cout << " : " << dev->description;
		}
		cout << endl;

		// další roazhraní
		dev = dev->next;
	}

	// uvolnění paměti
	pcap_freealldevs(alldevs);
	return;
}

/**
 * @brief funkce pro vypsání nápovědy
 * */
void Args::printHelp(){
	cout << "použití: `./sslsniff [-r file] [-i interface]` případně `./sslsniff --help` pro zobrazení této nápovědy" << endl;
	cout << "argumenty:" << endl;
	cout << "	`-h` nebo `--help` zobrazení nápovědy" << endl;
	cout << "	`-i interface` rozhraní, na kterém se bude poslouchat," << endl;
	cout << "	               bez hodnoty `interface` vypíše všechna dostupná zařízení" << endl;
	cout << "	`-r <file>` soubor se síťovým provozem" << endl;
	return;
}
// end Args.cpp
