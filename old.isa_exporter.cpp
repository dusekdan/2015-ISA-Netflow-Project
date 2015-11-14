#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <string>
#include <cstdlib>	// atoi and stuff

#include <netinet/in_systm.h>
#include <errno.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>

// Get opts parameter definitions
#define optarg_no 0
#define optarg_required 1
#define optarg_optinal 2

// Default values for parameters definition
#define defaultValue_input "stdin"
#define defaultValue_collectorAddress "127.0.0.1:2055"
#define defaultValue_interval 300
#define defaultValue_timeout 300
#define defaultValue_maxflows 50


using namespace std;

// TAKEN FROM TCPDUMP.org/pcap.html
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

// TAKEN FROM TCPDUMP.org END


const struct option longopts[] = 
{
	{"input",	optarg_required,	0,	'i'},
    {"collector",	optarg_required,	0,	'c'},
    {"interval", optarg_required, 0, 'I'},
    {"tcp-timeout", optarg_required, 0, 't'},
    {"max-flows", optarg_required, 0, 'm'},
    {0,	0,	0,	0},
};

typedef struct
{
	string inputFile;
	string collectorAddress;
	int interval;
	int timeout;
	int maxFlows;
	/*string inputFile = "";
	string collectorAddress = "127.0.0.1:2055";
	int interval = 300;
	int tcpTimeout = 300;
	int maxFlows = 50;*/

} T_Parameters;

T_Parameters Parameters;

void ParamInit();
void testParamInit(T_Parameters params);



void processPacket(u_char *args, const struct pcap_pkthdr *pHeader, const u_char *packet);

void processPacket(u_char *args, const struct pcap_pkthdr *pHeader, const u_char *packet)
{

}


int main(int argc, char * argv[])
{





	
	// Sets default values for params
	ParamInit();
	

	// Handles explicitly given params
	int goarg = 0;
	int index;
	
	while(goarg != -1)
	{
		goarg = getopt_long(argc, argv, "i:c:I:t:m:", longopts, &index);


		switch(goarg)
		{
			case 'i':
		        cout << "You hit i with:" << optarg << endl;
		        Parameters.inputFile = optarg;
	        break;

	      	case 'c':
		        cout << "You hit c with" << optarg << endl;
		        Parameters.collectorAddress = optarg;
	        break;

	        case 'I':
		        cout << "You hit Interval with " << optarg << endl;
		        Parameters.interval = atoi(optarg);
	        break;

	        case 't':
		        cout << "You hit timeout with " << optarg << endl;
		        Parameters.timeout = atoi(optarg);
	        break;

	        case 'm':
		        cout << "You hit maxflows with " << optarg << endl;
		        Parameters.maxFlows = atoi(optarg);
	        break;
		}
	}

	// Debug only - prints default & current values of params
	//testParamInit(Parameters);


	string testFile = "SamplePcaps/testoutputfile.pcap";
	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];

	pcap_t * pcap = pcap_open_offline(testFile.c_str(), pcapErrorBuffer);

	struct pcap_pkthdr *header;
	const u_char *data;

	u_int packetCount = 0;


	
	// Original 
	while(int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
	{
		cout << "Packet number: " << ++packetCount << " (size " << header->len << " bytes)" << endl;

		// epoch time...
		//cout << "Epoch time: " << header->ts.tv_sec << ":" << header->ts.tv_usec << endl;
		//printf("Epoch time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);


		for(u_int i = 0; (i < header->caplen); i++)
		{
			if((i%16)==0)
			{
				cout << "\n";
			}
			//printf("%.2x", data[i]);
		}

		cout << endl << endl;
	}

	

	return 0;
}




void ParamInit()
{
	// Default values specified by task assignment
	Parameters.inputFile = "stdin";
	Parameters.collectorAddress = "127.0.0.1:2055";
	Parameters.interval = 300;
	Parameters.timeout = 300;
	Parameters.maxFlows = 50;
}

void testParamInit(T_Parameters params)
{
	cout << "Given: " << params.inputFile 			<< endl << "Expected: " << defaultValue_input 				<< endl << "==========" << endl;
	cout << "Given: " << params.collectorAddress 	<< endl << "Expected: " << defaultValue_collectorAddress 	<< endl << "==========" << endl;
	cout << "Given: " << params.interval 			<< endl << "Expected: " << defaultValue_interval 			<< endl << "==========" << endl;
	cout << "Given: " << params.timeout 			<< endl << "Expected: " << defaultValue_timeout 			<< endl << "==========" << endl;
	cout << "Given: " << params.maxFlows 			<< endl << "Expected: " << defaultValue_maxflows 			<< endl << "==========" << endl;
}