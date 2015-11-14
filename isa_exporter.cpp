#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <string>
#include <cstdlib>	// atoi and stuff

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>


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


struct T_Flows 
{
	in_addr sourceAddress;
	in_addr destinationAddress;
	u_int	sourcePort;
	u_int	destinationPort;
	u_int	protocolType;

	// doba vzniku
	// doba trvání
	u_int		packetCount;
	u_int 	bytesTranfered;

	bool	flowExpired;

};

T_Parameters Parameters;

// TODO: Could be replaced by Vector, should be replaced by vector, will be replaced by vector
/*
int tflowsMaxSize 		= 10;
int tflowsStartIndex 	= 0;
T_Flows * procesedFlows = new T_Flows[tflowsMaxSize];*/


//T_Flows processedFlows[];

void ParamInit();
void testParamInit(T_Parameters params);



void processPacket(u_char *args, const struct pcap_pkthdr *pHeader, const u_char *packet);

void processPacket(u_char *args, const struct pcap_pkthdr *pHeader, const u_char *packet)
{

}


int main(int argc, char * argv[])
{

/// PARAMS HANDLING

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
		        //	cout << "You hit i with:" << optarg << endl;		// TODO: Remove this line
		        Parameters.inputFile = optarg;
	        break;

	      	case 'c':
		        //	cout << "You hit c with" << optarg << endl;			// TODO: Remove this line
		        Parameters.collectorAddress = optarg;
	        break;

	        case 'I':
		        //	cout << "You hit Interval with " << optarg << endl;	// TODO: Remove this line
		        Parameters.interval = atoi(optarg);
	        break;

	        case 't':
		        //	cout << "You hit timeout with " << optarg << endl;	// TODO: Remove this line
		        Parameters.timeout = atoi(optarg);
	        break;

	        case 'm':
		        //	cout << "You hit maxflows with " << optarg << endl;	// TODO: Remove this line
		        Parameters.maxFlows = atoi(optarg);
	        break;
		}
	}

	// Debug only - prints default & current values of params 	// TODO: Remove this line
	//testParamInit(Parameters);								// TODO: Remove this line


/// OPENING A PCAP FILE

	// Static testfile, TODO: Replace this with real input from --input/-i param
	//string testFile = "SamplePcaps/testoutputfile.pcap";
	
	// String for Error that may occur while reading pcap file
	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];


	/// Structures and variables for records from pcap file

	// Pointer in memory to packet
	const u_char *packet;

	// Paket header according to pcap representation
	struct pcap_pkthdr header;

	// Pointer to ethernet header
	struct ether_header *eptr;

	// Handle to file (and on online-exporter it would be device) from which the pcap stream is coming
	pcap_t *handle;

	// TODO: Figure this out
	int ether_offset = 0;

	struct ip *my_ip;
	struct tcphdr *my_tcp;


	// Counters for each supported protocol
	// TODO: Remove this
	int tcppacket = 0;
	int udppacket = 0;
	int igmptpacket = 0;
	int arppacket = 0;
	int icmppacket = 0;
	int other = 0;

	// Offline opening of the file, requires C-string representation of the input stream (xxx.c_str())
	// On error fills the pcapErrorBuffer with message 
	handle = pcap_open_offline(Parameters.inputFile.c_str(), pcapErrorBuffer);
		if(handle == NULL)
		{
			// Also immediate check if the operation was successful 
			// TODO: Termination of some kind? 
			// TODO: Add report from pcapErrorBuffer?
			cerr << "Unable to open file." ;
		}


/// READING A PCAP FILE (TODO: AGGREGATE TO FLOWS)

	// Looping through the records
	int packetCount = 0;
	while((packet = pcap_next(handle, &header)) != NULL)
	{
		packetCount++;

		eptr = (struct ether_header *) packet;

		switch(ntohs(eptr->ether_type))
		{
			case ETHERTYPE_IP:
				cout << "IP TYPE - ";	

				my_ip = (struct ip*) (packet+14);

				switch(my_ip->ip_p)
				{
					case 1: // ICMP
					cout << "ICMP PACKET" << endl;
					icmppacket++;
					break;
					case 2: // IGMP
					cout << "IGMP PACKET" << endl;
					igmptpacket++;
					break;

					case 6: // TCP
					cout << "TCP PACKET" << endl;
					tcppacket++;



						my_tcp = (struct tcphdr *) (my_ip + my_ip->ip_hl*4);	 

						cout << "Source port: " << (u_short) my_tcp->th_sport << " Destination port: " << (u_short) my_tcp->th_dport << endl;
					

						// Get all 5 values to identify flow
						// Check if flow exists
							// TRUE: Update metrics in the flow
							// FALSE: Create new flow


					break;

					case 17: // UDP
					cout << "UDP PACKET";
					udppacket++;
					break;

					default:
					other++;
					break;
				}



			break;

			case ETHERTYPE_ARP:
				cout << "ARP TYPE - ";
				arppacket++;
			break;

			default:
			other++;
			break;
		}


		cout << "#" << packetCount << " Packet length: " << header.len << " (bytes) | Time received: " << ctime((const time_t*)&header.ts.tv_sec) << endl;
	}


	cout << "Total stats: \n \tIGMP: " << igmptpacket << "x\n\tTCP: " << tcppacket << "x\n\tUDP: " << udppacket << "x\n\tARP: " << arppacket << "x\n\tICMP: " << icmppacket <<"x\n\tOthers: " << other << "x\n\t"  << endl;
	return 0;
}




void ParamInit()
{
	// Default values specified by task assignment
	Parameters.inputFile = "-";
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