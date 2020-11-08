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
#define CLIENT_HELLO 0x01
#define SERVER_HELLO 0x02

/**
 * @var conn
 * @brief struktura pro tcp spojení, kde #ssl a #srv_hello udává, zda-li jde o ssl spojení
 */
struct conn{
    timeval start_time;                  /**< začátek tcp spojení */
    char client_addr[INET6_ADDRSTRLEN];  /**< adresa klienta */
    char server_addr[INET6_ADDRSTRLEN];  /**< adresa serveru */
    u_short client_port;                 /**< port klienta */
    u_short server_port;                 /**< port serveru */
    unsigned int bytes = 0;              /**< bajty ssl spojení*/
    unsigned int packets = 0;            /**< počet paketů ssl spojení */
    string SNI;                          /**< SNI serveru */
    bool ssl = false;                    /**< jedná se o ssl spojení (byl poslán paket s client hello) */
    bool srv_hello = false;              /**< přišel paket se server hello */
    bool tcp_fin = false;                /**< přišel první FIN, čeká se na druhý */
};

/**
 * @var conn_vec
 * @brief vektor, obsahující aktivní tcp spojení uložené v struktuře #conn
 */
std::vector<conn> conn_vec;

/**
 * @brief vypsání ssl spojení ze struktury #c
 * @param c ssl spojení
 * @param ts čas paketu ukončujícího ssl spojení (pro výpočet trvání ssl spojení)
 */
void print_conn(conn* c, const timeval* ts){

    // struktura, pomocí níž se vypíše čas
    tm* time;
    time = localtime(&(c->start_time.tv_sec));

    // pro vypocet trvani
    timeval duration;
    timersub(ts, &(c->start_time), &duration);
    printf("%04d-%02d-%02d %02d:%02d:%02d.%06d,", time->tm_year+1900, time->tm_mon+1, time->tm_mday,
           time->tm_hour, time->tm_min, time->tm_sec, (int)(c->start_time.tv_usec));
    cout << c->client_addr << "," << c->client_port <<
         "," << c->server_addr << "," << c->SNI <<
         "," << c->bytes << "," << c->packets <<
         "," << duration.tv_sec << "." << duration.tv_usec << endl;
    return;
}

/**
 * @brief získání Server Name Indication z Client Hello
 * @param data ukazatel na data v Client Hello
 * @param c spojení, do kterého se má zapsat SNI
 */
void get_SNI(char* data, conn* c){
    data += 38;
    char sl = *data;
    data += sl + 1;
    u_short csl = htons(*((short *)&(*data)));
    data += csl + 2;
    char cml = *data;
    data += cml + 1;
    short extension_len = htons(*((short *)&(*data)));

    data += 2;
    u_short exts = 0;
    while(extension_len > exts){
        u_short ext_name = htons(*((short *)&(*data)));
        if(ext_name == 0){
            u_short off = 4;
            u_short sni_dl = htons(*((short *)&(*(data+2))));
            while(off < sni_dl) {
                char list_entry = *(data + off + 2);
                u_short le_len = htons(*((short *) &(*(data + off + 3))));
                if (list_entry == 0) {
                    c->SNI.clear();
                    char *hn = data + off + 5;
                    for (int i = 0; i < le_len; i++) {
                        /*if(hn[i] == 0){
                            return;
                        }*/
                        c->SNI.push_back(hn[i]);
                    }
                    return;
                }
                off += le_len + 5;
            }
        }
        exts = htons(*((short *)&(*(data+2))));
        data += exts + 4;
    }
    return;
}

/**
 * @brief funkce prohodí porty + adresy klienta a serveru
 * @param c tcp spojení
 */
void switch_client_server(conn *c){
    u_short tmp_p;
    char tmp_a[INET6_ADDRSTRLEN];
    strcpy(tmp_a, c->server_addr);
    strcpy(c->server_addr, c->client_addr);
    strcpy(c->client_addr, tmp_a);
    tmp_p = c->server_port;
    c->server_port = c->client_port;
    c->client_port = tmp_p;
    return;
}

/**
 * @brief funkce najde tcp spojení z #conn_vec , v případě nenalezení přidá spojení na konec
 * @param src_addr zdrojová adresa tcp spojení
 * @param dst_addr cílová adresa tcp spojenní
 * @param src_port zdrojový port tcp spojení
 * @param dst_port cílový port tcp spojení
 * @param ts čas příchodu paketu, v případě nenalezení spojení
 * @return ukazatel na nalezené/nově přidané spojení
 */
conn* check_conn(char* src_addr, char* dst_addr, u_short src_port, u_short dst_port, timeval ts){
    for (auto iter = conn_vec.begin();iter != conn_vec.end(); ++iter){
        conn *tmp = &(*iter);

        if((strcmp(tmp->client_addr, src_addr) == 0 && strcmp(tmp->server_addr, dst_addr) == 0) ||
           (strcmp(tmp->client_addr, dst_addr) == 0 && strcmp(tmp->server_addr, src_addr) == 0))
        {
            if((tmp->client_port == src_port && tmp->server_port == dst_port) ||
               (tmp->client_port == dst_port && tmp->server_port == src_port))
            {
                //nalezen
                return tmp;
            }
        }
    }
    //nenalezen
    conn tmp;
    memcpy(tmp.client_addr, src_addr, INET6_ADDRSTRLEN);
    memcpy(tmp.server_addr, dst_addr, INET6_ADDRSTRLEN);
    //prozatimni reseni, kdo je klient a kdo server se dozvim z handshaku
    tmp.client_port = src_port;
    tmp.server_port = dst_port;
    tmp.start_time = ts;
    conn_vec.push_back(tmp);
    return &conn_vec.back();
}


/**
 * @brief funkce odstraní spojení c z vektoru #conn_vec
 * @param c ukazatel na spojení, které se má odstranit
 */
void remove_from_vec(conn* c){
    for (auto iter = conn_vec.begin();iter != conn_vec.end(); ++iter){
        conn *tmp = &(*iter);
        if(strcmp(tmp->client_addr, c->client_addr) == 0 && strcmp(tmp->server_addr, c->server_addr) == 0){
            if(tmp->client_port == c->client_port && tmp->server_port == c->server_port){
                //nalezen
                conn_vec.erase(iter);
                return;
            }
        }
    }
}

/**
 * @brief funkce zíslká zdrojovou a cílovou adresu z ip hlavičky a posune offset o velikost ip hlavičky
 * @param iph hlavička ip (v4 nebo v6)
 * @param src_addr ukazatel do něhož se zapíše zdojová adresa
 * @param dst_addr ukazatel do něhož se zapíše cílová adresa
 * @param offset offset od původního začátku paketu
 */
void getAddr(ip* iph, char* src_addr,  char* dst_addr, u_short* offset){
    // jde o IPv4 hlavičku
    if (iph->ip_v == 4){
        // posunutí offsetu o velikost tcp hlavičky
        *offset = *offset + iph->ip_hl * 4;
        // získání adres
        inet_ntop(AF_INET, (void*)&(iph->ip_src), src_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void*)&(iph->ip_dst), dst_addr, INET_ADDRSTRLEN);
    }
        // jde o IPv6
    else {
        // posunutí offsetu o velikost tcp hlavičky
        *offset = *offset + sizeof(ip6_hdr);
        // získání adres
        ip6_hdr* ip6h = (ip6_hdr*)(iph);
        inet_ntop(AF_INET6, (void*)&(ip6h->ip6_src), src_addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void*)&(ip6h->ip6_dst), dst_addr, INET6_ADDRSTRLEN);
    }
}

/**
 * @brief funkce k výpisu informací o paketu
 * @param user -
 * @param header hlavička obsahující informace o paketu (například čas)
 * @param packet ukazatel na začátek paketu
 * */
void callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){

	// offset, na další hlavičku
	// ze začátku nastaven na velikost ethernetové hlavičky
	u_short offset = ETHERNET_SIZE;
	ip* iph = (ip*)(packet + offset);

    //pro ziskani adres
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    getAddr(iph, src_addr, dst_addr, &offset);

	// posunutí offsetu o velikost tcp protokolu
	tcphdr* tcp = (tcphdr*)(packet + offset);
	offset = offset + tcp->doff * 4;

	// získání portů
	// port zdroje a cíle
    u_short src_port, dst_port;
    src_port = htons(tcp->source);
    dst_port = htons(tcp->dest);

    conn* connection = check_conn(src_addr, dst_addr, src_port, dst_port, header->ts);
    connection->packets++;

    if(tcp->fin){
        if(connection->ssl && connection->srv_hello) {
            if (connection->tcp_fin) {
                print_conn(connection, &(header->ts));
                remove_from_vec(connection);
            } else {
                connection->tcp_fin = true;
            }
        }
        else {
            remove_from_vec(connection);
        }
        return;
    }


    char * data;
    u_short version;
    u_short length;
	while(header->caplen > (unsigned) offset + 5){
        data = (char*)(packet + offset);
	    if(*data == HANDSHAKE){
	        version = htons( *( (u_short *)&(*(data+1)) ) );
            if(version == TLS1_0 || version == TLS1_1 || version == TLS1_2) {
                char *hello_ptr = data + 5;
                if(*hello_ptr == CLIENT_HELLO){
                    connection->ssl = true;
                    if(strcmp(connection->client_addr, src_addr) != 0){
                        switch_client_server(connection);
                    }
                    get_SNI( hello_ptr, connection );
                    length = htons( *( (u_short *)&(*(data + 3)) ) );
                    connection->bytes += length;
                    offset += length;
                }
                else if(*hello_ptr == SERVER_HELLO){
                    connection->srv_hello = true;
                    length = htons( *( (short *)&(*(data + 3)) ) );
                    connection->bytes += length;
                    offset += length;
                }
                else{
                    offset += 1;
                }
            }
            else {
                offset += 1;
            }
	    }
	    else if(*data == CHANGE_CIPHER_SPEC || *data == ALERT || *data == APPLICATION_DATA){
            version = htons(*((short *)&(*(data+1))));
	        if(version == TLS1_0 || version == TLS1_1 || version == TLS1_2) {
                length = htons( *( (short *)&(*(data+3)) ) );
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
        conn_vec.clear();
		return 53;
	}
	conn_vec.clear();
	return 0;
}
// end ipk-sniffer.cpp
