#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <string.h>
#include <cstdlib>	// atoi and stuff
#include <vector>	// Surprisingly, vector needs to be added in order to work with vectors

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>	// inet_ntoa
#include <sys/socket.h>


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
} T_Parameters;


struct T_Flows 
{
	in_addr sourceAddress;
	in_addr destinationAddress;
	u_short	sourcePort;
	u_short	destinationPort;
	u_int	protocolType;

	// doba vzniku
	// doba trvání
	u_int	packetCount;
	u_int 	bytesTransfered;

	bool	flowExpired;


	const char* prettySourceAddress;
	const char* prettyDestinationAddress;
};

T_Parameters Parameters;
vector<T_Flows> processedFlows;

void createFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered)
{
	T_Flows newFlow;
	newFlow.sourceAddress = sourceAddress;
	newFlow.destinationAddress = destinationAddress;
	newFlow.sourcePort = sourcePort;
	newFlow.destinationPort = destinationPort;
	newFlow.protocolType = protocolType;
	newFlow.bytesTransfered = bytesTransfered;
	newFlow.packetCount++;
	newFlow.flowExpired = false;

	processedFlows.push_back(newFlow);
}

void createDebugFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, const char* prettySourceAddress, const char* prettyDestinationAddress)
{
	T_Flows newFlow;
	newFlow.sourceAddress = sourceAddress;
	newFlow.destinationAddress = destinationAddress;
	newFlow.sourcePort = sourcePort;
	newFlow.destinationPort = destinationPort;
	newFlow.protocolType = protocolType;
	newFlow.bytesTransfered = bytesTransfered;
	newFlow.packetCount++;
	newFlow.flowExpired = false;

	// For debugging purposes, I use pretty source address to be able to compare what am I actually putting in
	newFlow.prettySourceAddress = prettySourceAddress;
	newFlow.prettyDestinationAddress = prettyDestinationAddress;

	processedFlows.push_back(newFlow);
}

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
	//int ether_offset = 0;

	struct ip *my_ip;
	struct tcphdr *my_tcp;
	struct udphdr *my_udp;


	// Counters for each supported protocol
	// TODO: Remove this (or maybe just reposition)
	int tcppacket = 0;
	int udppacket = 0;
	int igmptpacket = 0;
	int arppacket = 0;
	int icmppacket = 0;
	int other = 0;



	// New flow record variables
	const char *prettySourceAddress, *prettyDestinationAddress;
	in_addr sourceAddress, destinationAddress;
	u_short sourcePort, destinationPort;
	u_int bytesTransfered;
	int protocolType;
	const char* auxBuff;

	// Offline opening of the file, requires C-string representation of the input stream (xxx.c_str())
	// On error fills the pcapErrorBuffer with message 
	handle = pcap_open_offline(Parameters.inputFile.c_str(), pcapErrorBuffer);
		if(handle == NULL)
		{
			// Immediate check if the operation was successful 
			cerr << "Error occured: ";
			cerr << pcapErrorBuffer;		// Error description provided by pcap_* function
			cerr << endl;
			exit(1);
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
					
					// Get all 5 values to identify flow

						// Data load
						sourceAddress		= (in_addr) my_ip->ip_src;
						destinationAddress 	= my_ip->ip_dst; 
						sourcePort 			= (u_short) my_tcp->th_sport;
						destinationPort 	= (u_short) my_tcp->th_dport;
						protocolType		= 6;	// Given by case
						bytesTransfered		= header.len;

						// TESTING CORRECTNESS OF DATA
							// Creation of pretty (printable) destination & source address
							// inet_ntoa (and ether_ntoa) returns value in a static buffer that is overwritten by subsequent call, therefore I need to copy string somewhere first

							auxBuff = inet_ntoa(my_ip->ip_src);
							prettySourceAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

							auxBuff = inet_ntoa(my_ip->ip_dst);
							prettyDestinationAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

							cout << "Source address: " << prettySourceAddress << " Destination address: " << prettyDestinationAddress << endl;
							cout << "Source port: "	<<  sourcePort	<< " Destination port: " << destinationPort << endl;

					// Check if flow exists
						
						// In case that vector is empty, I add T_Flows record right away
						if(processedFlows.empty())
						{
							// TODO: Replace this line with createFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, prettySourceAddress);
							createDebugFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, prettySourceAddress, prettyDestinationAddress);
	
							// Debug only TODO: Remove this line
							cout << "ADDED FIRST RECORD TO processedFlows (current processedflows: " << processedFlows.size() << ")" << endl;
						}
						// Flows are not empty
						else
						{

							// Initialize on true, set to false if flow exists (and is discovered by for loop)
							bool createNewFlow = true;

							// Iterating through vector of flows
							for(vector<T_Flows>::iterator it = processedFlows.begin(); it != processedFlows.end(); ++it)
							{

								if(it->sourceAddress.s_addr == sourceAddress.s_addr && it->destinationAddress.s_addr == destinationAddress.s_addr && it->sourcePort == sourcePort && it->destinationPort == destinationPort && it->protocolType == protocolType)
								{
									// TRUE: Update metrics in the flow 
									// TODO: DO THAT
									cout << "JUST RUN OVER THE EXISTING FLOW (S: " << it->prettySourceAddress << ":" << it->sourcePort <<", D:" << it->prettyDestinationAddress << ":"<< it->destinationPort <<") (current processedflows: " << processedFlows.size() << ")"  << endl;
									
									// Do not create another flow record, terminate the for loop (optimalization)
									createNewFlow = false;
									break;
								}
							}

							// Condition is true when no record for the tuple of sourceAddress, destinationAddress, sourcePort, destinationPort & protocolType is found
							if(createNewFlow)
							{
									// TODO: Replace this line with createFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, prettySourceAddress);
									// Creates flow record for the current tuple
									createDebugFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, prettySourceAddress, prettyDestinationAddress);
									
									// Set need for creating new flow back to false
									createNewFlow = false;
									// TODO: Debug only, remove this
									cout << "ADDED NEW FLOW TO processedFlows (S: " << prettySourceAddress << ":" << sourcePort <<", D:" << prettyDestinationAddress << ":"<< destinationPort <<") (current processedflows: " << processedFlows.size() << ")" << endl;
							}
						}
					break;

					case 17: // UDP
						cout << "UDP PACKET" << endl;
						udppacket++;

						my_udp = (struct udphdr *) (my_ip + my_ip->ip_hl*4);


					// Get all 5 values to identify flow
						
						// Data load
						sourceAddress		= (in_addr) my_ip->ip_src;
						destinationAddress 	= my_ip->ip_dst; 
						sourcePort 			= (u_short) my_udp->uh_sport;
						destinationPort 	= (u_short) my_udp->uh_dport;
						protocolType		= 6;	// Given by case
						bytesTransfered		= header.len;

						// TESTING CORRECTNESS OF DATA
							// Creation of pretty (printable) destination & source address
							// inet_ntoa (and ether_ntoa) returns value in a static buffer that is overwritten by subsequent call, therefore I need to copy string somewhere first

							auxBuff = inet_ntoa(my_ip->ip_src);
							prettySourceAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

							auxBuff = inet_ntoa(my_ip->ip_dst);
							prettyDestinationAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

							cout << "Source address: " << prettySourceAddress << " Destination address: " << prettyDestinationAddress << endl;
							cout << "Source port: "	<<  sourcePort	<< " Destination port: " << destinationPort << endl;

					// Check if flow exists
						
						// In case that vector is empty, I add T_Flows record right away
						if(processedFlows.empty())
						{
							// TODO: Replace this line with createFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, prettySourceAddress);
							createDebugFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, prettySourceAddress, prettyDestinationAddress);
	
							// Debug only TODO: Remove this line
							cout << "ADDED FIRST RECORD TO processedFlows (current processedflows: " << processedFlows.size() << ")" << endl;
						}
						// Flows are not empty
						else
						{

							// Initialize on true, set to false if flow exists (and is discovered by for loop)
							bool createNewUDP = true;

							// Iterating through vector of flows
							for(vector<T_Flows>::iterator it = processedFlows.begin(); it != processedFlows.end(); ++it)
							{

								if(it->sourceAddress.s_addr == sourceAddress.s_addr && it->destinationAddress.s_addr == destinationAddress.s_addr && it->sourcePort == sourcePort && it->destinationPort == destinationPort && it->protocolType == protocolType)
								{
									// TRUE: Update metrics in the flow 
									// TODO: DO THAT
									cout << "JUST RUN OVER THE EXISTING FLOW (S: " << it->prettySourceAddress << ":" << it->sourcePort <<", D:" << it->prettyDestinationAddress << ":"<< it->destinationPort <<") (current processedflows: " << processedFlows.size() << ")"  << endl;
									
									// Do not create another flow record, terminate the for loop (optimalization)
									createNewUDP = false;
									break;
								}
							}

							// Condition is true when no record for the tuple of sourceAddress, destinationAddress, sourcePort, destinationPort & protocolType is found
							if(createNewUDP)
							{
									// TODO: Replace this line with createFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, prettySourceAddress);
									// Creates flow record for the current tuple
									createDebugFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, prettySourceAddress, prettyDestinationAddress);
									
									// Set need for creating new flow back to false
									createNewUDP = false;
									// TODO: Debug only, remove this
									cout << "ADDED NEW FLOW TO processedFlows (S: " << prettySourceAddress << ":" << sourcePort <<", D:" << prettyDestinationAddress << ":"<< destinationPort <<") (current processedflows: " << processedFlows.size() << ")" << endl;
							}
						}
					break;

					default:
					other++;
					break;
				}



			break;

			case ETHERTYPE_ARP:
				cout << "ARP TYPE" << endl;
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