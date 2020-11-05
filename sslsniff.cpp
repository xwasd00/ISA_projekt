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
#include <vector>
#include "Args.h"

using namespace std;

#define ETHERNET_SIZE 14
#define TCP_PROTOCOL 6
#define CHANGE_CIPHER_SPEC 0x14
#define ALERT 0x15
#define HANDSHAKE 0x16
#define APPLICATION_DATA 0x17
#define TLS1_0 0x301
#define TLS1_1 0x302
#define TLS1_2 0x303


struct conn{
    timeval start_time;
    char client_addr[INET6_ADDRSTRLEN];
    char server_addr[INET6_ADDRSTRLEN];
    u_short client_port;
    u_short server_port;
    int bytes = 0;
    int packets = 0;
    string SNI;
    bool ssl = false;
};
std::vector<conn> conn_vec;

void print_conn(conn* c, const timeval* ts){
    // struktura, pomocí níž se vypíše čas
    tm* time;
    time = localtime(&(ts->tv_sec));
    timeval duration;
    timersub(ts, &(c->start_time), &duration);
    printf("%04d-%02d-%02d %02d:%02d:%02d.%d,", time->tm_year+1900, time->tm_mon, time->tm_mday,
           time->tm_hour, time->tm_min, time->tm_sec, (int)(ts->tv_usec));
    cout << c->client_addr << " " << c->client_port <<
         " , " << c->server_addr << " " << c->SNI <<
         " ," << c->packets << "," << c->bytes <<
         "," << duration.tv_sec << "." << duration.tv_usec << endl;
    return;
}

/**
 * @brief funkce, která uloží do src_port a dst_port zdrojový a cílový port z protokolu a nastaví offset
 * @param tcp ukazatel na začátek tcp hlavičky
 * @param src_port zdrojový port
 * @param dst_port cílový port
 */
void getPort(tcphdr* tcp, u_short* src_port, u_short* dst_port){
		*src_port = tcp->th_sport<<8 | tcp->th_sport>>8;
		*dst_port = tcp->th_dport<<8 | tcp->th_dport>>8;
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
 * @param iph ipv6 hlavička
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
 * @brief ...
 * @param user -
 * @param header hlavička obsahující informace o paketu (například čas)
 * @param packet ukazatel na začátek paketu
 * */
void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){

	// offset, na další hlavičku
	// ze začátku nastaven na velikost ethernetové hlavičky
	short offset = ETHERNET_SIZE;
	ip* iph = (ip*)(packet + offset);

    //pro ziskani adres
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
	// jde o IPv4 hlavičku
	if (iph->ip_v == 4){
		getTcp(iph, &offset);// posunutí offsetu o velikost tcp hlavičky
        // získání adres
        inet_ntop(AF_INET, (void*)&(iph->ip_src), src_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void*)&(iph->ip_dst), dst_addr, INET_ADDRSTRLEN);
	}
	// jde o IPv6
	else {
		getTcp((ip6_hdr*)(iph), &offset);// posunutí offsetu o velikost hlavičky
        // získání adres
        ip6_hdr* ip6h = (ip6_hdr*)(iph);
		inet_ntop(AF_INET6, (void*)&(ip6h->ip6_src), src_addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void*)&(ip6h->ip6_dst), dst_addr, INET6_ADDRSTRLEN);
	}

	// posunutí offsetu o velikost tcp protokolu
	tcphdr* tcp = (tcphdr*)(packet + offset);
	offset = offset + tcp->doff * 4;

	// získání portů
	// port zdroje a cíle
    u_short src_port, dst_port;
    getPort(tcp, &src_port, &dst_port);

    conn* connection;
    bool found = false;
    for (auto iter = conn_vec.begin();iter != conn_vec.end(); ++iter){
        conn *tmp = &(*iter);
        if((strcmp(tmp->client_addr, src_addr) == 0 && strcmp(tmp->server_addr, dst_addr) == 0) ||
                (strcmp(tmp->client_addr, dst_addr) == 0 && strcmp(tmp->server_addr, src_addr) == 0))
        {
            if((tmp->client_port == src_port && tmp->server_port == dst_port) ||
                    (tmp->client_port == dst_port && tmp->server_port == src_port))
            {
                //nalezen
                found = true;
                connection = tmp;
                break;
            }
        }
    }
    //nenalezen
    if(!found){
        conn tmp;
        memcpy(tmp.client_addr, src_addr, INET6_ADDRSTRLEN);
        memcpy(tmp.server_addr, dst_addr, INET6_ADDRSTRLEN);
        //prozatimni reseni, kdo je klient a kdo server se dozvim z handshaku
        tmp.client_port = src_port;
        tmp.server_port = dst_port;
        tmp.start_time = header->ts;
        conn_vec.push_back(tmp);
        connection = &conn_vec.back();
    }
    //vystup connection -> ukazatel na nalezeny prvek
    connection->packets++;

    if(tcp->fin){
        //TODO: přepsání do funkce
        //TODO: vymazani struktury
        if(connection->ssl) {

            print_conn(connection, &(header->ts));

        }
        else{
            //FIN -> remove
        }
        cout << "FIN" << endl << endl;
        return;
    }


    char * data = (char*)(packet + offset);
    short version;
    short length;
	while(header->caplen >(unsigned) offset + 5){
        data = (char*)(packet + offset);

	    if(*data == HANDSHAKE){
	        version = htons( *( (short *)&(*(data+1)) ) );

            if(version == TLS1_0 || version == TLS1_1 || version == TLS1_2) {
                connection->ssl = true;
                //TODO: pokud client hello -> nastaveni znaku spojeni na ssl + SNI
                //TODO: pokud client hello -> nastavit klienta a server (adresy + porty)
                //TODO: pokud server hello -> kontrola portu a serveru + pripadne nastaveni znaku ssl
                length = htons( *( (short *)&(*(data + 3)) ) );
                connection->bytes += length;
                offset += length;
            }
            else {
                offset += sizeof(char);
            }

	    }
	    else if(*data == CHANGE_CIPHER_SPEC || *data == ALERT || *data == APPLICATION_DATA){
            version = htons(*((short *)&(*(data+1))));
            //version = (short *)&(*(data+1));
            //*version = htons(*version);

	        if(version == TLS1_0 || version == TLS1_1 || version == TLS1_2) {
                length = htons( *( (short *)&(*(data+3)) ) );
                //*length = htons(*length);
                connection->bytes += length;
                offset += length;

            }
            else {
                offset += sizeof(char);
            }

	    }
	    else {
            offset += sizeof(char);
        }

	}
	
	//debug
	//printPacket((char*)packet, offset, 0);
	//printf("%02hhx  %02hhx  %02hhx\n", *data, *(data+1), *(data+2));
	//printPacket((char*)packet, header->caplen, offset);
	//cout << endl;
    return;
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
