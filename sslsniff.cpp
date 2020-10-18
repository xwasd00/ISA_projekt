/*************************************************/
/*********** Monitoring SSL spojení **************/
/********** projekt do předmětu ISA **************/
/*********** Michal Sova (xsovam00) **************/
/*************************************************/

#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <cstring>
#include <arpa/inet.h>
#include "Args.h"

using namespace std;

#define ETHERNET_SIZE 14
#define TCP_PROTOCOL 6
int cnt = 1;

/**TODO: upravit
 * @brief funkce, která uloží do src_port a dst_port zdrojový a cílový port z protokolu a nastaví offset
 * @param tcp ukazatel na začátek tcp hlavičky
 * @param src_port zdrojový port
 * @param dst_port cílový port
 * @param offset offset od původního začátku paketu
 */
/*
void getPort(tcphdr* tcp, u_short* src_port, u_short* dst_port){
		*src_port = tcp->th_sport<<8 | tcp->th_sport>>8;
		*dst_port = tcp->th_dport<<8 | tcp->th_dport>>8;
		return;
}
*/

//debug print
void printPacket(char* payload, short len, short offset){
    char buffer[17] = {0};
    short start = offset % 16;
    short space = offset % 8;
    short end_hex = (start + 15) % 16;

    for( short i = offset; i < len; i++){

        if(i % 16 == start){
            printf("0x%04x: ", i);
        }
        if(i % 8 == space){
            cout << " ";
        }

        printf("%02hhx ", payload[i]);

        if( payload[i] > 31 && payload[i] < 126){
            buffer[(i - start) % 16] = payload[i];
        }
        else{
            buffer[(i - start) % 16] = '.';
        }

        if(i % 16 == end_hex){
            cout << "  " << buffer << endl;
            memset(&buffer, 0, sizeof(buffer));
        }
    }

    if(len % 16 != start){
        short fill = 16 - (len-offset)%16;
        for( int i = 0; i < fill; i++){
            cout  << "   ";
        }
        cout << "  " <<  buffer << endl;
    }
    return;
}


/**
 * @brief funkce, která nastaví offset na tcp hlavičku
 * @param iph ip hlavička
 * @param offset offset od původního začátku paketu
 */
void getTcp(ip* iph, short* offset){
	
    if(iph->ip_p == TCP_PROTOCOL){
		// posunutí offsetu:
		*offset = *offset + iph->ip_hl * 4;
    }
    else{
        //TODO:
		cerr << "neni tcp" << endl;
    }
}

/**
 * @brief funkce, která nastaví offset na tcp hlavičku
 * @param iph ip hlavička
 * @param offset offset od původního začátku paketu
 */
void getTcp(ip6_hdr* iph, short* offset){
	
	if(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP_PROTOCOL){
		// posunutí offsetu:
		*offset = *offset + sizeof(ip6_hdr);
	}
	else{
		//TODO:
		cerr << "neni tcp"<<endl;
	}
}

/**
 * @brief funkce, která získá uloží do src_addr a dst_addr zdrojovou a cílovou adresu
 * @param iph ip hlavička
 * @param src_addr zdrojová adresa
 * @param dst_addr cílová adresa
 */
void getAddress(ip* iph, char* src_addr, char* dst_addr){

	// získání adres:
	inet_ntop(AF_INET, (void*)&(iph->ip_src), src_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, (void*)&(iph->ip_dst), dst_addr, INET_ADDRSTRLEN);
	return;
}

/**
 * @brief funkce, která uloží do src_addr a dst_addr zdrojovou a cílovou adresu
 * @param iph ip hlavička
 * @param src_addr zdrojová adresa
 * @param dst_addr cílová adresa
 */
void getAddress(ip6_hdr* iph, char* src_addr, char* dst_addr){

	// získání adres:
	inet_ntop(AF_INET6, (void*)&(iph->ip6_src), src_addr, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, (void*)&(iph->ip6_dst), dst_addr, INET6_ADDRSTRLEN);
	return;
}

/**
 * @brief funkce k výpisu informací o paketu
 * @param user -
 * @param header hlavička obsahující informace o paketu (například čas)
 * @param packet ukazatel na začátek paketu
 * */
void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){
	cout << "paket: " << cnt << endl;
	cnt++;
	// struktura, pomocí níž se lehce vypíše čas
	/*
	tm* time;
	time = localtime(&(header->ts.tv_sec));	
	*/

	// offset, na další hlavičku
	// ze začátku nastaven na velikost ethernetové hlavičky
	short offset = ETHERNET_SIZE;
	ip* iph = (ip*)(packet + offset);

	// jde o IPv4 hlavičku
	if (iph->ip_v == 4){
		// posunutí offsetu o velikost tcp hlavičky
		getTcp(iph, &offset);
	}
	// jde o IPv6
	else {
		// posunutí offsetu o velikost hlavičky
		getTcp((ip6_hdr*)(iph), &offset);
	}

	// posunutí offsetu o velikost tcp protokolu
	tcphdr* tcp = (tcphdr*)(packet + offset);
	offset = offset + tcp->th_off * 4;

	//TODO: check FIN from tcp
	if(header->caplen <= offset+1){
		if(tcp->th_flags & TH_FIN){
			cout << "FIN" << endl << endl;
			return;
		}
		else{
			cout << "pouze hlavicka" << endl << endl;
			return;
		}
	}

	char* data = (char*)(packet + offset);
	//TODO: check handshake
	if(*data == 22){
		cout << "handshake" << endl << endl;
		return;
	}
	//TODO: other data
	if(*data == 20 || *data == 23){
		cout << "key exchange nebo application data -> LENGTH += ...; COUNT++;" << endl << endl;
		return;
	}

	cout << "ostatni data" << endl << endl;
	
	//debug
	//printPacket((char*)packet, offset, 0);
	//printf("%02hhx  %d\n", *data, *data);
	//printPacket((char*)packet, header->caplen, offset);
	//cout << endl;




	// získání portů
	// port zdroje a cíle
	//u_short src_port, dst_port;
	//getPort(tcp, &src_port, &dst_port);
	
	// adresa zdroje a cíle
	/*char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];
	if (iph->ip_v == 4){
        // získání adres
        getAddress(iph, src_addr, dst_addr);
    }
    // jde o IPv6
    else {
        // získání adres
        getAddress((ip6_hdr*)(iph), src_addr, dst_addr);
    }*/
}
/**
 * @returns 0 všechno v pořádku
 * @returns 50 chyba při parsování argumentů
 * @returns 51 chyba při otvírání rozhraní
 * @returns 52 chyba při nastavení filtru
 * @returns 53 chyba při přijímání paketu
 */
int main(int argc, char** argv){
	pcap_t *handle;
	char errbuff[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 ip;

	// parsování argumentů
	Args arg;
	int retval = arg.getOpts(argc, argv); 
	switch(retval){
		case 0:
			break;
		case -1:
			return 0;
			break;
		default:
			return retval;
			break;
	}
	
	// otevření rozhraní, nastavení filtru a vytvoření callback funkce
	// vytvořeno podle: https://www.tcpdump.org/pcap.html

	
	// otevření rozhraní (podle argumentu DEV) pro analyzování
	if(arg.file){
		handle = pcap_open_offline(arg.filename.data(), errbuff);
	}
	else{
		handle = pcap_open_live(arg.dev.data(), BUFSIZ, 0, 200, errbuff);
	}

	if (handle == NULL) {
		cerr << "Couldn't open device " << errbuff << endl;
		return 51;
	}
	
	// nastavení filtru , a jeho zkompilování
	if (!arg.file){
		if (pcap_lookupnet(arg.dev.data(), &ip, &mask, errbuff) == -1) {
			cerr << "Couldn't get netmask for device " << errbuff << endl;
			ip = 0;
			mask = 0;
		}
	}
	if (pcap_compile(handle, &fp, "tcp", 0, ip) == -1) {
		cerr << "Couldn't parse filter " << pcap_geterr(handle) << endl;
		return 52;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		cerr << "Couldn't install filter" << pcap_geterr(handle) << endl;
		return 52;
	}
	

	// smyčka s callback funkcí
	// funkce callback() => vypsání paketu
	if (pcap_loop(handle, -1, callback, nullptr) != 0){
		cerr << "pcap_loop error : " << pcap_geterr(handle) << endl;
        return 53;
	}
	return 0;
}
// end ipk-sniffer.cpp
