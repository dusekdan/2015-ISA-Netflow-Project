#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <string.h>
#include <cstdlib>	// atoi and stuff
#include <vector>	// Surprisingly, vector needs to be added in order to work with vectors
#include <bitset>
#include <cmath>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>	// inet_ntoa
#include <sys/socket.h>

#include <sstream>

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


// Other
#define ETHERNET_HEADER_SIZE 14

// Protocol number defines
#define protoNumber_ICMP 1
#define protoNumber_IGMP 2
#define protoNumber_TCP 6
#define protoNumber_UDP 17


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


	struct timeval startTime;
	struct timeval lastPacketArrival;
	struct timeval endTime;


	u_int	packetCount = 0;
	u_int 	bytesTransfered = 0;

	bool	flowExpired = false;


	bool 	finArrived = false;

	uint8_t 	typeOfService;

	bitset<8> tcpFlags;
	uint8_t	tcpFlagsForCollector	= 0;

	const char* prettySourceAddress;
	const char* prettyDestinationAddress;
};

struct packetHeader
{
	uint16_t	version	=	5;
	uint16_t	count;
	uint32_t	sysUpTime;
	uint32_t	unix_secs;
	uint32_t	unix_nsecs;
	uint32_t	flow_sequence;
	uint8_t		engine_type;
	uint8_t		engine_id;
	uint16_t	sampling_interval;

};

struct packetBody
{
	in_addr	srcaddr;
	in_addr	dstaddr;
	in_addr	nexthop;
	uint16_t	input	=	0;
	uint16_t	output	=	0;
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint32_t	First;
	uint32_t	Last;
	uint16_t	srcport;
	uint16_t	dstport;
	uint8_t		pad1	=	0;
	uint8_t		tcp_flags;
	uint8_t		prot;
	uint8_t		tos;
	uint16_t	src_as 	 =	0;
	uint16_t	dst_as   =	0;
	uint8_t		src_mask =	0;
	uint8_t		dst_mask = 	0;
	uint16_t	pad2 	 =	0;	
};


struct outgoingPacket
{
	struct packetHeader 	pHeader;
	struct packetBody	 	pBody[30];
};

T_Parameters Parameters;
vector<T_Flows> processedFlows;
vector<T_Flows> expiredFlows;

int totalFlowCount = 0;


double doubleTime(long timeSec, long timeMSec);
void updateFlow();
void exportFlows();
void expireFlows();
void ParamInit();
void testParamInit(T_Parameters params);
void debug_PrintFlowInfo(vector<T_Flows>::iterator it);
void expireLongestInactiveConnection(long currentTimeSec, long currentTimeMiliSec);
void handleFlowUpdate(bitset<8> tcpFlags, struct pcap_pkthdr header, in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, int protocolType, bool *createNewFlow);


void handleFlowUpdate(bitset<8> tcpFlags, struct pcap_pkthdr header, in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, int protocolType, bool *createNewFlow)
{
	for(vector<T_Flows>::iterator it = processedFlows.begin(); it != processedFlows.end(); ++it)
	{
		// Check whether this exact flow exists within processedFlows
		if(	
			it->destinationAddress.s_addr == destinationAddress.s_addr && 
			it->sourceAddress.s_addr == sourceAddress.s_addr && 
			it->destinationPort == destinationPort && 
			it->protocolType == protocolType &&
			it->sourcePort == sourcePort										
	   	  )
			{
				// Based on that, update flow metrics
				it->bytesTransfered = it->bytesTransfered+ header.len;
				it->packetCount = it->packetCount+1;
				it->lastPacketArrival.tv_sec = header.ts.tv_sec;
				it->lastPacketArrival.tv_usec = header.ts.tv_usec;
			

				// FIN flag reached - this flow expires right now
				if(tcpFlags.test(0))
				{
					cout << "FIN REACHED - this flow is updated and expired" << endl;
					it->finArrived = true;
					it->flowExpired = true;

						cout << " ... already exists, updated statistics of processedFlows (" << processedFlows.size() << ")"  << endl;
						cout << "\tPackets in this flow: " << it->packetCount << endl;
						cout << "\tTransfered in total: " << it->bytesTransfered  << " (bytes) " << endl;
						cout << "\tConnection time: " << (doubleTime(it->lastPacketArrival.tv_sec, it->lastPacketArrival.tv_usec) - doubleTime(it->startTime.tv_sec, it->startTime.tv_usec)) << endl;

					expiredFlows.push_back(*it);
					processedFlows.erase(it);
					it--;
				}
				else if(tcpFlags.test(2))
				{
					cout << "RST REACHED - this flow and its opposite is updated and expired";
					
					// FINish current flow
					it->finArrived = true;
					it->flowExpired = true;

						cout << " ... already exists, updated statistics of processedFlows (" << processedFlows.size() << ")"  << endl;
						cout << "\tPackets in this flow: " << it->packetCount << endl;
						cout << "\tTransfered in total: " << it->bytesTransfered  << " (bytes) " << endl;
						cout << "\tConnection time: " << (doubleTime(it->lastPacketArrival.tv_sec, it->lastPacketArrival.tv_usec) - doubleTime(it->startTime.tv_sec, it->startTime.tv_usec)) << endl;
					

					expiredFlows.push_back(*it);
					processedFlows.erase(it);
					it--;


					// Track & hunt down its opposite
					// TODO or not? ;)

				}
				else
				{
					cout << " ... already exists, updated statistics of processedFlows (" << processedFlows.size() << ")"  << endl;

					cout << "\tPackets in this flow: " << it->packetCount << endl;
					cout << "\tTransfered in total: " << it->bytesTransfered  << " (bytes) " << endl;
					cout << "\tConnection time: " << (doubleTime(it->lastPacketArrival.tv_sec, it->lastPacketArrival.tv_usec) - doubleTime(it->startTime.tv_sec, it->startTime.tv_usec)) << endl;
				}

				*createNewFlow = false;
				break;
		}
	}
}

void createTCPFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, bitset<8> tcpFlags, uint8_t typeOfService, uint8_t tcpFlagsForCollector)
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

	// Startime + last packet arrival
	newFlow.startTime.tv_sec = startTime.tv_sec;
	newFlow.startTime.tv_usec = startTime.tv_usec;
	newFlow.lastPacketArrival.tv_sec = startTime.tv_sec;
	newFlow.lastPacketArrival.tv_usec = startTime.tv_usec;

	// For debugging purposes, I use pretty source address to be able to compare what am I actually putting in
	newFlow.prettySourceAddress = prettySourceAddress;
	newFlow.prettyDestinationAddress = prettyDestinationAddress;

	newFlow.typeOfService = typeOfService;
	newFlow.tcpFlagsForCollector = tcpFlagsForCollector;


	newFlow.tcpFlags = tcpFlags;

	if(tcpFlags.test(0))
	{
		// FIN
		newFlow.finArrived = true;
		newFlow.flowExpired = true;
		expiredFlows.push_back(newFlow);
	}
	else
	{
		processedFlows.push_back(newFlow);
	}	

	totalFlowCount++;
}

void processPacketCheck(struct pcap_pkthdr header, long intervalStartTimeSec, long intervalStartTimeMsec, bool *recordNewInterval)
{

	//cout << "INTERVAL CHECK: " << 

	// Interval check
	if(	(doubleTime(header.ts.tv_sec, header.ts.tv_usec) - doubleTime(intervalStartTimeSec, intervalStartTimeMsec)) >= Parameters.interval && !expiredFlows.empty())
	{
		// Export it
		cout << "=== EXPORT OCCURED (interval run out) [ " << doubleTime(header.ts.tv_sec, header.ts.tv_usec) <<  "-"<< doubleTime(intervalStartTimeSec, intervalStartTimeMsec) <<" = "<< (doubleTime(header.ts.tv_sec, header.ts.tv_usec) - doubleTime(intervalStartTimeSec, intervalStartTimeMsec)) <<"] ===" << endl;
		exportFlows();
		cout << "===========================================" << endl;

		*recordNewInterval = true;
	}

	// Loop through all the flows (processedFlows)
	for(vector<T_Flows>::iterator it = processedFlows.begin(); it != processedFlows.end(); ++it)
	{
		// TCP Timeout check
		long currentTimeSec 	=	header.ts.tv_sec;
		long currentTimeMiliSec	=	header.ts.tv_usec;

		double timeIdle = (doubleTime(currentTimeSec, currentTimeMiliSec) - doubleTime(it->lastPacketArrival.tv_sec, it->lastPacketArrival.tv_usec));

		cout << "Flow ID: " << it->prettySourceAddress << ":" << it->sourcePort << " -> " << it->prettyDestinationAddress << ":" << it->destinationPort << "(PT: " << it->protocolType << ")" << endl;
		cout << "Idle time: " << timeIdle  << endl;

		// This only evaluates true when timeout is reached/exceeded 
		if(timeIdle >= Parameters.timeout)
		{
			cout << "This packet triggered expiration (TCPTIMEOUT) of the flow identified by: " << it->prettySourceAddress << ":" << it->sourcePort << " -> " << it->prettyDestinationAddress << ":" << it->destinationPort << "(PT: " << it->protocolType << ")" << endl;	
			expiredFlows.push_back(*it);
			processedFlows.erase(it);
			it--;
		}

	}
}

void createDebugFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, uint8_t typeOfService)
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

	// Startime + last packet arrival
	newFlow.startTime.tv_sec = startTime.tv_sec;
	newFlow.startTime.tv_usec = startTime.tv_usec;
	newFlow.lastPacketArrival.tv_sec = startTime.tv_sec;
	newFlow.lastPacketArrival.tv_usec = startTime.tv_usec;

	// For debugging purposes, I use pretty source address to be able to compare what am I actually putting in
	newFlow.prettySourceAddress = prettySourceAddress;
	newFlow.prettyDestinationAddress = prettyDestinationAddress;

	// UDP & ICMP goes to expired instantly
	if(protocolType == 17 || protocolType == 1)
	{
		// Expired should be expired
		newFlow.flowExpired = true;
		expiredFlows.push_back(newFlow);
	}
	else
	{
		processedFlows.push_back(newFlow);
	}

	totalFlowCount++;
}



double doubleTime(long timeSec, long timeMSec)
{
	string smsec = to_string(timeMSec);

	stringstream sstm;
	string aux = "0.";

	sstm << aux;

	for(int i = 0; i < (6-smsec.size()); i++)
	{
		sstm << "0";
	}

	sstm << timeMSec;

	string results;
	results = sstm.str();

	double realMsec  = stod(results);
	return (double) (timeSec + realMsec);
}


void debug_PrintFlowInfo(vector<T_Flows>::iterator it)
{
	cout << "Transfered in total: " << it->bytesTransfered  << " (bytes) " << endl;
	cout << "Packets in this flow: " << it->packetCount << endl;
	cout << "Current flow duration: " << (it->lastPacketArrival.tv_sec - it->startTime.tv_sec) << " seconds since the begining of UNIX." << endl;
}


void expireLongestInactiveConnection(long currentTimeSec, long currentTimeMiliSec)
{
	long oldestFoundSec = currentTimeSec;
	long oldestFoundMSec = currentTimeMiliSec;
	vector<T_Flows>::iterator auxIter;

	for(vector<T_Flows>::iterator it2 = processedFlows.begin(); it2 != processedFlows.end(); ++it2)
	{
		if( (it2->lastPacketArrival.tv_sec < oldestFoundSec) || ( it2->lastPacketArrival.tv_sec == oldestFoundSec && it2->lastPacketArrival.tv_usec < oldestFoundMSec))
		{
			oldestFoundSec = it2->lastPacketArrival.tv_sec;
			oldestFoundMSec = it2->lastPacketArrival.tv_usec;
			auxIter = it2;
		}
	}

	cout << "The oldest found non-expired packet sits  with time of " << oldestFoundSec << "(" << oldestFoundMSec << ")" << endl;

	expiredFlows.push_back(*auxIter);
	processedFlows.erase(auxIter);
}


long firstPacketTimeSec;
long firstPacketTimeMSec;


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
		        Parameters.inputFile = optarg;
	        break;

	      	case 'c':
		        Parameters.collectorAddress = optarg;
	        break;

	        case 'I':
		        Parameters.interval = atoi(optarg);
	        break;

	        case 't':
		        Parameters.timeout = atoi(optarg);
	        break;

	        case 'm':
		        Parameters.maxFlows = atoi(optarg);
	        break;
		}
	}

/// OPENING A PCAP FILE

	// String for Error that may occur while reading pcap file
	char pcapErrorBuffer[PCAP_ERRBUF_SIZE];

	/// Structures and variables for records from pcap file

	// Pointer in memory to packet
	const u_char *packet;

	// Paket header according to pcap representation
	struct pcap_pkthdr header;

	// Pointer to ethernet header
	struct ether_header *eptr;

	// Handle to file (and on online-exporter it would be device) which the pcap stream is coming from
	pcap_t *handle;


	// Structures for different headers
	struct ip *my_ip;
	struct tcphdr *my_tcp;
	struct udphdr *my_udp;
	struct icmphdr *my_icmp;
	struct igmphdr *my_igmp;

	// Counters for each supported protocol
	int tcppacket = 0;
	int udppacket = 0;
	int igmptpacket = 0;
	int arppacket = 0;
	int icmppacket = 0;
	int other = 0;

	bitset<8> tcpFlags;
	long currentTimeSec;
	long currentTimeMiliSec;

	// New flow record auxiliary variables
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


/// READING A PCAP FILE

	long intervalStartTimeSec;
	long intervalStartTimeMsec;
	bool recordNewInterval = true;

	bool firstRun = true;



	// Looping through the records
	int packetCount = 0;
	while((packet = pcap_next(handle, &header)) != NULL)
	{
		// Increasing the total count of packets
		packetCount++;

		// Initiation variables for Interval check
		if(recordNewInterval)
		{
			intervalStartTimeSec = header.ts.tv_sec;
			intervalStartTimeMsec = header.ts.tv_usec;
			recordNewInterval = false;
		}


		// Store first packet time
		if(firstRun)
		{
			firstPacketTimeSec 	=	header.ts.tv_sec;
			firstPacketTimeMSec	=	header.ts.tv_usec;
			firstRun = false;
		}

		// Flow control variable (ethernet header)
		eptr = (struct ether_header *) packet;

		// Current packet information printed out
		cout << "#" << packetCount << " Packet length: " << header.len << " (bytes) | Time received: " << ctime((const time_t*)&header.ts.tv_sec);


		// With each packet -> check all the flows; expire expired flows, export when interval runs out
		processPacketCheck(header, intervalStartTimeSec, intervalStartTimeMsec, &recordNewInterval);

		// Magic cast and shift about ETHERNET_HEADER forwards
		my_ip = (struct ip*) (packet + ETHERNET_HEADER_SIZE);		

		// Do not forget about all the endians, network to host switch
		switch(ntohs(eptr->ether_type))
		{
			case ETHERTYPE_IP:

				switch(my_ip->ip_p)
				{

					case protoNumber_TCP: // TCP
						
						// Increase TCP packet counter
						tcppacket++;

						// Get basic data from tcphdr structure
						my_tcp = (struct tcphdr *) (packet + ETHERNET_HEADER_SIZE + my_ip->ip_hl*4);	 
						
						// Get all important flow specific values
						sourceAddress		= (in_addr) my_ip->ip_src;
						destinationAddress 	= my_ip->ip_dst; 
						sourcePort 			= (u_short) my_tcp->th_sport;
						destinationPort 	= (u_short) my_tcp->th_dport;
						protocolType		= 6;	// Given by case
						bytesTransfered		= header.len;
						tcpFlags 			= my_tcp->th_flags;


						// TCP Timeout check
						currentTimeSec 	=	header.ts.tv_sec;
						currentTimeMiliSec	=	header.ts.tv_usec;

						// Creation of pretty (printable) destination & source address
						// inet_ntoa (and ether_ntoa) returns value in a static buffer that is overwritten by subsequent call, therefore I need to copy string somewhere first
						auxBuff = inet_ntoa(my_ip->ip_src);
						prettySourceAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);
						auxBuff = inet_ntoa(my_ip->ip_dst);
						prettyDestinationAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

// ERASE-START
								cout << "TCP PACKET " << prettySourceAddress << ":" << sourcePort << " -> " << prettyDestinationAddress << ":" << destinationPort;

										cout << endl << "flags: ";

										if(tcpFlags.test(0))
										{
											cout << "FIN arrived ";
										}

										if(tcpFlags.test(2))
										{
											cout << "RST arrived ";
										}

										if(tcpFlags.test(4))
										{
											cout << "ACK arrived ";
										}

										cout << endl;
// ERASE-END

						// In case that vector is empty, I add T_Flows record right away
						if(processedFlows.empty())
						{
							createTCPFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress, tcpFlags, my_ip->ip_tos, my_tcp->th_flags);
		
							cout << " ... added first record to processedFlows/expiredFlows (PF:" << processedFlows.size() << " | EF: "<< expiredFlows.size() <<")" << endl;
						}
						// Flows are not empty
						else
						{
							// Initialize on true, set to false if flow exists (and is discovered by for loop)
							bool createNewFlow = true;

							// Checks existence of the flow, eventually updates the existing
							handleFlowUpdate(tcpFlags, header, sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, &createNewFlow);

							// Condition is true when no record for the tuple of sourceAddress, destinationAddress, sourcePort, destinationPort & protocolType is found
							if(createNewFlow)
							{

								// Case where internal memory for flow storage reaches its maximum limit (given by param -m / --max-flows)
								if(processedFlows.size() >= Parameters.maxFlows)
								{
									// None of the flows is expired yet
									if(expiredFlows.size() == 0)
									{
										// Force expire the first (oldest) flow recorded
										expireLongestInactiveConnection(currentTimeSec, currentTimeMiliSec);
									}
									break;
								}

								// Creates flow record for the current tuple
								createTCPFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress, tcpFlags, my_ip->ip_tos, my_tcp->th_flags);
								
								// Set need for creating new flow back to false
								createNewFlow = false;
								
								cout << " ... new flow record created in processedFlows (PF:" << processedFlows.size() << " | EF: "<< expiredFlows.size() <<")" << endl;
							}
						}
					break;

					// Using same branch for all UDP, IGMP, ICMP packets
					case protoNumber_UDP: 	
					case protoNumber_IGMP:
					case protoNumber_ICMP:

						my_udp = (struct udphdr *) (packet + ETHERNET_HEADER_SIZE + my_ip->ip_hl*4);

						// Protocol specific values
						if(my_ip->ip_p == protoNumber_UDP)
						{
							udppacket++;
							protocolType = protoNumber_UDP;

							sourcePort 			= 	(u_short) my_udp->uh_sport;
							destinationPort 	= 	(u_short) my_udp->uh_dport;

						}
						else if(my_ip->ip_p == protoNumber_IGMP)
						{
							igmptpacket++;
							protocolType = protoNumber_IGMP;

							sourcePort = 0;
							destinationPort = 0;
						}
						else if(my_ip->ip_p == protoNumber_ICMP)
						{
							icmppacket++;
							protocolType = protoNumber_ICMP;

							sourcePort = 0;
							destinationPort = 0;
						}
		
						// Common values for all protocols
						sourceAddress		= 	(in_addr) my_ip->ip_src;
						destinationAddress 	= 	(in_addr) my_ip->ip_dst; 
						bytesTransfered		= 	header.len;

						// Creation of pretty (printable) destination & source address
						// inet_ntoa (and ether_ntoa) returns value in a static buffer that is overwritten by subsequent call, therefore I need to copy string somewhere first
						auxBuff = inet_ntoa(my_ip->ip_src);
						prettySourceAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

						auxBuff = inet_ntoa(my_ip->ip_dst);
						prettyDestinationAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

						// Creation & Information about whats going on
						createDebugFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress, my_ip->ip_tos);
						cout << "UDP PACKET " << prettySourceAddress << ":" << sourcePort << " -> " << prettyDestinationAddress << ":" << destinationPort  << " ... added to expiredFlows (" << expiredFlows.size() << ")" << endl;
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


		cout << endl;
	}

	// expire everything
	expireFlows();

	cout << "=== EXPORT OCCURED (end of file reached) ===" << endl;
	exportFlows();
	cout << "===========================================" << endl;
	expiredFlows.clear();

	cout << "Total stats: \n \tIGMP: " << igmptpacket << "x\n\tTCP: " << tcppacket << "x\n\tUDP: " << udppacket << "x\n\tARP: " << arppacket << "x\n\tICMP: " << icmppacket <<"x\n\tOthers: " << other << "x\n\t"  << "Totalflows: " << totalFlowCount << endl;
	return 0;
}

void exportFlows()
{

	int packetsToExport;
	double packetDivision = ceil(expiredFlows.size() / 30.0);
	packetsToExport = (int) packetDivision;
	cout << "Packets to be exported: " << packetsToExport << endl;
	
	// This is how many export packets are really going to be exported
	
	for(int packetNumber = 0; packetNumber < packetsToExport; packetNumber++)
	{

		struct outgoingPacket outPacket;

		cout << "Exporting packet #" << packetNumber << " to collector:" << endl;

	
			int flowsPacked = 0;
			for(vector<T_Flows>::iterator flow = expiredFlows.begin(); (flow != expiredFlows.end() && flowsPacked != 30 ); ++flow)
			{

				cout << "[";
					cout << flow->prettySourceAddress << ":" << flow->sourcePort << "->" << flow->prettyDestinationAddress << ":" << flow->destinationPort << "(" << flow->protocolType << ")";
				cout << "]" << endl;


				// Source address
				outPacket.pBody[flowsPacked].srcaddr = flow->sourceAddress;
				// Destination address
				outPacket.pBody[flowsPacked].dstaddr = flow->destinationAddress;
				// Packet count
				outPacket.pBody[flowsPacked].dPkts	 = flow->packetCount;
				// Bytes transfered (Octet == Byte, caused by historic inconsistency)
				outPacket.pBody[flowsPacked].dOctets = flow->bytesTransfered;

				uint32_t auxFirstTime = (uint32_t) ((doubleTime(flow->startTime.tv_sec, flow->startTime.tv_usec) - doubleTime(firstPacketTimeSec, firstPacketTimeMSec))*1000);
				outPacket.pBody[flowsPacked].First 	= auxFirstTime;

				uint32_t auxLastTime = (uint32_t)  ((doubleTime(flow->lastPacketArrival.tv_sec, flow->lastPacketArrival.tv_usec) - doubleTime(firstPacketTimeSec, firstPacketTimeMSec))*1000);	
				outPacket.pBody[flowsPacked].Last 	= auxLastTime;


				// Source port
				outPacket.pBody[flowsPacked].srcport  = flow->sourcePort;
				// Destination port
				outPacket.pBody[flowsPacked].dstport  = flow->destinationPort;
				// TCP Flags
				outPacket.pBody[flowsPacked].tcp_flags = flow->tcpFlagsForCollector;
				// Protocol type (UDP/IGMP/ICMP/TCP)
				outPacket.pBody[flowsPacked].prot = flow->protocolType;
				// Type of service
				outPacket.pBody[flowsPacked].tos = flow->typeOfService;

				// After I pack it to the packets, I also remove it from the expiredFlows
				expiredFlows.erase(flow);
				flow--;

				// Increase the counter of packed packets
				flowsPacked++;
			}


			// Here the packet header should be created


	}
		
	expiredFlows.clear();
}

void expireFlows()
{
	for(vector<T_Flows>::iterator flow = processedFlows.begin(); flow != processedFlows.end(); ++flow)
	{
		expiredFlows.push_back(*flow);	
	}
	
	processedFlows.clear();
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