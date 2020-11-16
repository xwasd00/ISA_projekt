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

#define ETHERNET_SIZE       14
#define ETH_P_8021Q         0x8100
#define TCP_PROTOCOL        6

//typ ssl spojení
#define CHANGE_CIPHER_SPEC   0x14
#define ALERT                0x15
#define HANDSHAKE            0x16
#define APPLICATION_DATA     0x17

//verze ssl
#define SSL3_0 0x300
#define TLS1_0 0x301
#define TLS1_1 0x302
#define TLS1_2 0x303
#define TLS1_3 0x304

// typ zprávy handshake
#define CLIENT_HELLO          0x01 // 1
#define SERVER_HELLO          0x02 // 2

/**
 * @var conn
 * @brief struktura pro tcp spojení, kde #ssl a #srv_hello udává, zda-li jde o ssl spojení
 */
struct conn{
    timeval start_time;                  /**< začátek tcp spojení */
    timeval end_time;                    /**< konec spojení */
    char client_addr[INET6_ADDRSTRLEN];  /**< adresa klienta */
    char server_addr[INET6_ADDRSTRLEN];  /**< adresa serveru */
    u_short client_port;                 /**< port klienta */
    u_short server_port;                 /**< port serveru */
    unsigned int bytes = 0;              /**< bajty ssl spojení*/
    unsigned int packets = 0;            /**< počet paketů ssl spojení */
    string SNI;                          /**< SNI serveru */
    bool ssl = false;                    /**< jedná se o ssl spojení (byl poslán paket s client hello) */
    bool srv_hello = false;              /**< přišel paket se server hello */
    bool client_fin = false;             /**< přišel FIN od klienta */
    bool server_fin = false;             /**< přišel FIN od serveru */
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
void print_conn(conn* c){

    // struktura, pomocí níž se vypíše čas
    tm* time;
    time = localtime(&(c->start_time.tv_sec));

    // pro výpočet trvaní ssl spojení
    timeval duration;
    timersub(&(c->end_time), &(c->start_time), &duration);

    //výpis ve formátu:
    //<timestamp>,<client ip>,<client port>,<server ip>,<SNI>,<bytes>,<packets>,<duration sec>
    printf("%04d-%02d-%02d %02d:%02d:%02d.%06ld,", time->tm_year+1900, time->tm_mon+1, time->tm_mday,
           time->tm_hour, time->tm_min, time->tm_sec, (c->start_time.tv_usec));
    cout << c->client_addr << "," << c->client_port <<
         "," << c->server_addr << "," << c->SNI <<
         "," << c->bytes << "," << c->packets <<
         "," << duration.tv_sec << ".";
    printf("%06ld\n", duration.tv_usec);
    return;
}

/**
 * @brief získání Server Name Indication z Client Hello
 * @param data ukazatel na data v Client Hello
 * @param c spojení, do kterého se má zapsat SNI
 */
void get_SNI(char* data, conn* c){

    //Client Random(32) + Handshake Header(4) + Client Version(2)
    data += 38;

    //Session ID
    char sl = *data;
    data += sl + 1;

    //Cipher suites
    u_short csl = htons(*((short *)&(*data)));
    data += csl + 2;

    //Compression methods
    char cml = *data;
    data += cml + 1;

    //Extensions length
    int extension_len = htons(*((short *)&(*data)));
    data += 2;
    int exts = 0;
    int size = 0;

    //cyklus, hledající SNI v rozšířeních
    while(extension_len > size){

        //jméno rozšíření
        u_short ext_name = htons(*((short *)&(*data)));

        //jde o SNI
        if(ext_name == 0){

            //prohledání všech list entry
            char* sni_data;
            sni_data = data + 4;

            char list_entry = *(sni_data + 2);
            if (list_entry == 0) {

                //délka hostname
                u_short hostname_len = htons(*((short *) &(*(sni_data + 3))));

                //zapsání SNI do ssl spojení
                c->SNI.clear();
                char *hn = sni_data + 5;
                for (int i = 0; i < hostname_len; i++) {
                    c->SNI.push_back(hn[i]);
                }
                return;
            }
            return;
        }

        //další rozšíření
        exts = htons(*((short *)&(*(data+2))));
        data += exts + 4;
        size += exts + 4;
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

    //cyklus přes všechny prvky conn_vec
    for (auto iter = conn_vec.begin();iter != conn_vec.end(); ++iter){
        conn *tmp = &(*iter);

        //konrola aadres a portů
        if((strcmp(tmp->client_addr, src_addr) == 0 && strcmp(tmp->server_addr, dst_addr) == 0) ||
           (strcmp(tmp->client_addr, dst_addr) == 0 && strcmp(tmp->server_addr, src_addr) == 0))
        {
            if((tmp->client_port == src_port && tmp->server_port == dst_port) ||
               (tmp->client_port == dst_port && tmp->server_port == src_port))
            {
                //spojení nalezeno
                return tmp;
            }
        }
    }

    //spojení nenalezeno -> vytvoření a vložení nového
    conn tmp;

    //prozatimní řešení, kdo je klient a kdo server se dozvím z Handshake
    memcpy(tmp.client_addr, src_addr, INET6_ADDRSTRLEN);
    memcpy(tmp.server_addr, dst_addr, INET6_ADDRSTRLEN);
    tmp.client_port = src_port;
    tmp.server_port = dst_port;

    //časové razítko prvního paketu
    tmp.start_time = ts;
    conn_vec.push_back(tmp);
    return &conn_vec.back();
}

/**
 * @brief funkce odstraní spojení c z vektoru #conn_vec
 * @param c ukazatel na spojení, které se má odstranit
 */
void remove_from_vec(conn* c){

    //cyklus přes všechny prvky conn_vec
    for (auto iter = conn_vec.begin();iter != conn_vec.end(); ++iter){
        conn *tmp = &(*iter);

        //kontrola adres a portů
        if(strcmp(tmp->client_addr, c->client_addr) == 0 && strcmp(tmp->server_addr, c->server_addr) == 0){
            if(tmp->client_port == c->client_port && tmp->server_port == c->server_port){

                //spojení nalezeno
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
 * @returns 0 vse ok
 * @returns 1 ip hlavička nenalezena
 */
int getAddr(ip* iph, char* src_addr,  char* dst_addr, unsigned* offset){
    // jde o IPv4 hlavičku
    if (iph->ip_v == 4){
        // posunutí offsetu o velikost tcp hlavičky
        *offset = *offset + iph->ip_hl * 4;
        // získání adres
        inet_ntop(AF_INET, (void*)&(iph->ip_src), src_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void*)&(iph->ip_dst), dst_addr, INET_ADDRSTRLEN);
        return 0;
    }
        // jde o IPv6
    else if(iph->ip_v == 6){
        // posunutí offsetu o velikost tcp hlavičky
        *offset = *offset + sizeof(ip6_hdr);
        // získání adres
        ip6_hdr* ip6h = (ip6_hdr*)(iph);
        inet_ntop(AF_INET6, (void*)&(ip6h->ip6_src), src_addr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void*)&(ip6h->ip6_dst), dst_addr, INET6_ADDRSTRLEN);
        return 0;
    }
    return 1;
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
	unsigned offset = ETHERNET_SIZE;
	ip* iph = (ip*)(packet + offset);



    //pro ziskani adres + nastavení offsetu
    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    if(getAddr(iph, src_addr, dst_addr, &offset) != 0){
        return;
    }

	// posunutí offsetu o velikost tcp protokolu
	tcphdr* tcp = (tcphdr*)(packet + offset);
	offset = offset + tcp->doff * 4;

	// získání portů
	// port zdroje a cíle
    u_short src_port, dst_port;
    src_port = htons(tcp->source);
    dst_port = htons(tcp->dest);

    //získání ukazatele na aktuální spojení z vektoru spojení (conn_vec)
    conn* connection = check_conn(src_addr, dst_addr, src_port, dst_port, header->ts);

    //přičtení paketu ke spojení
    connection->packets++;

    //možná je poslední
    connection->end_time = header->ts;

    char * data;
    u_short version;
    unsigned length;

    // cyklus hledá v paketu ssl hlavičky
	while(header->caplen >= offset + 5){
        data = (char*)(packet + offset);

        /// HANDSHAKE
        //možná následuje Handshake
        if(*data == HANDSHAKE){
            //verze ssl
	        version = htons( *( (u_short *)&(*(data+1)) ) );
            if(version == TLS1_0 || version == TLS1_1 ||
                version == TLS1_2 || version == SSL3_0 || version == TLS1_3) {

                //typ handshake
                char *hello_ptr = data + 5;
                /// Client Hello
                if(*hello_ptr == CLIENT_HELLO){
                    connection->ssl = true;

                    //v případě, že adresa+port serveru a klienta jsou obráceně
                    if(strcmp(connection->client_addr, src_addr) != 0){
                        switch_client_server(connection);
                    }
                    //získání Server Name Indication
                    get_SNI( hello_ptr, connection );
                    //přičtení velikosti ssl zprávy do celkové velikosti ssl spojení
                    length = htons( *( (u_short *)&(*(data + 3)) ) );
                    connection->bytes += length;
                    //přeskočení dat o délku zprávy -> délka + velikost délky(2) + verze(2) + typ(1)
                    offset += length + 5;
                }
                /// Server Hello
                else if(*hello_ptr == SERVER_HELLO){
                    connection->srv_hello = true;
                    if(strcmp(connection->server_addr, src_addr) != 0) {
                        switch_client_server(connection);
                    }

                        //přičtení velikosti ssl zprávy do celkové velikosti ssl spojení
                    length = htons( *( (short *)&(*(data + 3)) ) );
                    connection->bytes += length;
                    //přeskočení dat o délku zprávy -> délka + velikost délky(2) + verze(2) + typ(1)
                    offset += length + 5;
                }
                /// Certificate, Server key exchange, Server hello done,...
                else {

                    //přičtení velikosti ssl zprávy do celkové velikosti ssl spojení
                    length = htons( *( (short *)&(*(data + 3)) ) );
                    connection->bytes += length;
                    //přeskočení dat o délku zprávy -> délka + velikost délky(2) + verze(2) + typ(1)
                    offset += length + 5;
                }
            }
            //nesprávná verze ssl -> není ssl hlavička
            else {
                offset += 1;
            }
	    }


        /// APPLICATION DATA, ALERT, ...
        //jde nejspíš o Application data, Alert, ...
	    else if(*data == CHANGE_CIPHER_SPEC || *data == ALERT ||
	            *data == APPLICATION_DATA){

	        version = htons(*((short *)&(*(data+1))));

            //verze ssl
	        if(version == TLS1_0 || version == TLS1_1 ||
	            version == TLS1_2 || version == SSL3_0 || version == TLS1_3) {
                //přičtení velikosti ssl zprávy do celkové velikosti ssl spojení
                length = htons( *( (short *)&(*(data+3)) ) );
                connection->bytes += length;
                //přeskočení dat o délku zprávy -> délka + velikost délky(2) + verze(2) + typ(1)
                offset += length + 5;
                if(strcmp(connection->SNI.data(), "preview.redd.it") == 0){
                    printf("%d : %02hhx %02hhx\n", length, *(data+3), *(data+4));
                }
            }

	        //nesprávná verze ssl -> není ssl
            else {
                offset += 1;
            }
	    }

	    //není ssl -> další bajt
	    else {
            offset += 1;
        }
    }

    //jde o FIN
    if(tcp->fin){

        //fin od klienta
        if(strcmp(connection->client_addr, src_addr) == 0 && connection->client_port == src_port &&
            strcmp(connection->server_addr, dst_addr) == 0 && connection->server_port == dst_port){
            connection->client_fin = true;
        }
        //fin od serveru
        else if(strcmp(connection->server_addr, src_addr) == 0 && connection->server_port == src_port &&
                strcmp(connection->client_addr, dst_addr) == 0 && connection->client_port == dst_port){
            connection->server_fin = true;
        }
        //jde o ssl spojení
        if(connection->ssl && connection->srv_hello) {


            //FIN ze serveru i od klienta -> vypsání spojení
            if (connection->client_fin && connection->server_fin) {
                print_conn(connection);
                remove_from_vec(connection);
            }
        }
        //není ssl
        else {
            return;
        }

    }
    //RST -> okamžité ukončení spojení
    else if(tcp->rst){
        if(connection->ssl && connection->srv_hello) {
            print_conn(connection);
            remove_from_vec(connection);
        }
    }


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
		    //vše OK
			break;
		case -1:
		    //vypsána nápověda/rozhraní -> konec programu
			return 0;
			break;
		default:
		    //chybně zadány argumenty
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
    pcap_freecode(&fp);
	pcap_close(handle);
/*
	// vypsání neukončeného spojení (v případě zachytávání ze souboru)
    for(auto connection = conn_vec.begin(); connection != conn_vec.end(); ++connection) {
        if (connection->ssl && connection->srv_hello) {
            print_conn(&(*connection));
        }
    }
    */
	return 0;
}
// end ipk-sniffer.cpp
