#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <string.h>
#include <cstdlib>
#include <vector>
#include <bitset>
#include <cmath>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>	// inet_ntoa
#include <sys/socket.h>
#include <sys/types.h>
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
	{	"input",		optarg_required,	0,	'i'		},
    {	"collector",	optarg_required,	0,	'c'		},
    {	"interval", 	optarg_required, 	0, 	'I'		},
    {	"tcp-timeout", 	optarg_required, 	0, 	't'		},
    {	"max-flows", 	optarg_required, 	0, 	'm'		},
    {0,0,0,0},
};

typedef struct
{
	string inputFile;
	string collectorAddress 				= 	"127.0.0.1";
	int port 								= 	2055;
	int interval;
	int timeout;
	int maxFlows;
} T_Parameters;


struct T_Flows 
{
	in_addr		sourceAddress;
	in_addr 	destinationAddress;
	u_short		sourcePort;
	u_short		destinationPort;
	u_int		protocolType;
	struct 		timeval startTime;
	struct 		timeval lastPacketArrival;
	struct 		timeval endTime;
	u_int		packetCount 				= 	0;
	u_int 		bytesTransfered 			= 	0;
	bool		flowExpired 				= 	false;
	bool 		finArrived 					= 	false;
	uint8_t 	typeOfService;
	bitset<8> 	tcpFlags;
	uint8_t		tcpFlagsForCollector		= 	0;
	const char* prettySourceAddress;
	const char* prettyDestinationAddress;
};

struct packetHeader
{
	uint16_t	version						=	htons(5);
	uint16_t	count;
	uint32_t	sysUpTime;
	uint32_t	unix_secs;
	uint32_t	unix_nsecs;
	uint32_t	flow_sequence;
	uint8_t		engine_type 				= 	0;
	uint8_t		engine_id 					= 	0;
	uint16_t	sampling_interval			= htons(0);

};

struct packetBody
{
	in_addr		srcaddr;
	in_addr		dstaddr;
	in_addr		nexthop;
	uint16_t	input						=	htons(0);
	uint16_t	output						=	htons(0);
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint32_t	First;
	uint32_t	Last;
	uint16_t	srcport;
	uint16_t	dstport;
	uint8_t		pad1						=	0;
	uint8_t		tcp_flags;
	uint8_t		prot;
	uint8_t		tos;
	uint16_t	src_as 	 					=	htons(0);
	uint16_t	dst_as   					=	htons(0);
	uint8_t		src_mask 					=	0;
	uint8_t		dst_mask 					= 	0;
	uint16_t	pad2 	 					=	htons(0);	
};


struct outgoingPacket
{
	struct packetHeader 	pHeader;
	struct packetBody	 	pBody[30];
};

T_Parameters Parameters;
vector<T_Flows> processedFlows;
vector<T_Flows> expiredFlows;

long firstPacketTimeSec;
long firstPacketTimeMSec;
long currentPacketTimeSec;
long currentPacketTimeMSec;

int totalFlowCount 				= 	0;

double doubleTime(long timeSec, long timeMSec);
void exportFlows();
void expireFlows();
void ParamInit();
void testParamInit(T_Parameters params);
void expireLongestInactiveConnection(long currentTimeSec, long currentTimeMiliSec);
void handleFlowUpdate(bitset<8> tcpFlags, struct pcap_pkthdr header, in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, int protocolType, bool *createNewFlow, uint8_t tcpFlagsForCollector);
void processPacketCheck(struct pcap_pkthdr header, long intervalStartTimeSec, long intervalStartTimeMsec, bool *recordNewInterval);
void createExpiredFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, uint8_t typeOfService);
void createTCPFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, bitset<8> tcpFlags, uint8_t typeOfService, uint8_t tcpFlagsForCollector);
void setCollectorHostParameters(string sArg);



/**
  *	Handles parameters, Opens pcap file, loops through packets, process them, exports them
  *	@param 	int		argc 	Numeric value of arguments received
  *	@param 	char*	argv 	Array of arguments received
  */
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
	      		// Dealing with various -c possibilities
		       setCollectorHostParameters(optarg);
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
	struct ip 		*my_ip;
	struct tcphdr 	*my_tcp;
	struct udphdr 	*my_udp;
	struct icmphdr 	*my_icmp;
	struct igmphdr 	*my_igmp;

	// Counters for each supported protocol
	int tcppacket 	= 	0;
	int udppacket 	= 	0;
	int igmptpacket = 	0;
	int arppacket 	= 	0;
	int icmppacket 	= 	0;
	int other 		= 	0;

	bitset<8> 	tcpFlags;
	long 		currentTimeSec;
	long 		currentTimeMiliSec;

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
	
	bool recordNewInterval 			= true;
	bool firstRun 					= true;



	// Looping through the records
	int packetCount = 0;
	while((packet = pcap_next(handle, &header)) != NULL)
	{
		// Increasing the total count of packets
		packetCount++;

		// Initiation variables for Interval check
		if(recordNewInterval)
		{
			intervalStartTimeSec 	= 	header.ts.tv_sec;
			intervalStartTimeMsec 	= 	header.ts.tv_usec;
			recordNewInterval 		= 	false;
		}


		// Store first packet time
		if(firstRun)
		{
			firstPacketTimeSec 		=	header.ts.tv_sec;
			firstPacketTimeMSec		=	header.ts.tv_usec;
			firstRun = false;
		}

		currentPacketTimeSec 		=	header.ts.tv_sec;
		currentPacketTimeMSec 		=	header.ts.tv_usec;

		// Flow control variable (ethernet header)
		eptr = (struct ether_header *) packet;

		// Debug Current packet information printed out (time hint: ctime((const time_t*)&header.ts.tv_sec))

		// With each packet -> check all the flows; expire expired flows, export when interval runs out
		processPacketCheck(header, intervalStartTimeSec, intervalStartTimeMsec, &recordNewInterval);

		// Magic cast and shift about ETHERNET_HEADER forwards
		my_ip = (struct ip*) (packet + ETHERNET_HEADER_SIZE);		

		// Do not forget about all the endians => network to host switch
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

						// In case that vector is empty, I add T_Flows record right away
						if(processedFlows.empty())
						{
							createTCPFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress, tcpFlags, my_ip->ip_tos, my_tcp->th_flags);
						}
						// Flows are not empty
						else
						{
							// Initialize on true, set to false if flow exists (and is discovered by for loop)
							bool createNewFlow = true;

							// Checks existence of the flow, eventually updates the existing
							handleFlowUpdate(tcpFlags, header, sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, &createNewFlow, my_tcp->th_flags);

							// Condition is true when no record for the tuple of sourceAddress, destinationAddress, sourcePort, destinationPort & protocolType is found
							if(createNewFlow)
							{

								// Case where internal memory for flow storage reaches its maximum limit (given by param -m / --max-flows)
								if(processedFlows.size() >= Parameters.maxFlows)
								{
									// Force expire the first (oldest) flow recorded
									expireLongestInactiveConnection(currentTimeSec, currentTimeMiliSec);
								}

								// Creates flow record for the current tuple
								createTCPFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress, tcpFlags, my_ip->ip_tos, my_tcp->th_flags);
								
								// Set need for creating new flow back to false
								createNewFlow = false;
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
						createExpiredFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress, my_ip->ip_tos);
					break;

					default:
					other++;
					break;
				}
			break;
			default:
			other++;
			break;
		}
	}

	// End of file reached
	expireFlows();	// Expire remaining active flows
	exportFlows();	// And export it

	return 0;
}

/**
  *	Checks whether Interval run-out or TCP timed-out + takes action
  *	@param 	pcap_pkthdr	header 					Packet header, used for gathering information about current packet
  *	@param 	long 		intervalStartTimeSec 	Time in seconds since 1970, recorded when interval started
  *	@param 	long 		intervalStartTimeMsec 	Time in miliseconds since 1970, recorder when interval started
  * @param 	bool		*recordNewInterval 		Pointer to boolean recordNewInterval specifying whether new interval-time should be recorded with the next loop
  */
void processPacketCheck(struct pcap_pkthdr header, long intervalStartTimeSec, long intervalStartTimeMsec, bool *recordNewInterval)
{
	// Interval check
	if((doubleTime(header.ts.tv_sec, header.ts.tv_usec) - doubleTime(intervalStartTimeSec, intervalStartTimeMsec)) >= Parameters.interval && !expiredFlows.empty())
	{
		// Export it
		exportFlows();

		// When interval was triggered, record new time (for the next trigger)
		*recordNewInterval = true;
	}

	// Loop through all the flows (processedFlows)
	for(vector<T_Flows>::iterator it = processedFlows.begin(); it != processedFlows.end(); ++it)
	{
		// TCP Timeout check
		long currentTimeSec 		=	header.ts.tv_sec;
		long currentTimeMiliSec		=	header.ts.tv_usec;

		// Time for the given connection was inactive
		double timeIdle				=	(doubleTime(currentTimeSec, currentTimeMiliSec) - doubleTime(it->lastPacketArrival.tv_sec, it->lastPacketArrival.tv_usec));

		// Check whether the timeout was exceeded
		if(timeIdle >= Parameters.timeout)
		{
			expiredFlows.push_back(*it);		// Expire flow that timed-out
			processedFlows.erase(it);			// Erase the flow from processedFlows
			it--;								// Adjust the pointer in order to avoid unpredictable behavior
		}

	}
}


/**
  *	Creates expired flow (typically useful for UDP, ICMP & IGMP)
  * @param	in_addr		sourceAddress 				Source address of the flow
  *	@param	in_addr		destinationAddress 			Destination address of the flow
  * @param 	u_short		sourcePort					Source port of the flow
  *	@param 	u_short 	destinationPort				Destination port of the flow
  * @param 	u_int		protocolType				Protocol type of the flow (UDP = 17, IGMP = 2, ICMP = 1)
  *	@param 	u_int		bytesTransfered				Initial number of bytes that were transfered within this flow
  *	@param 	timeval		startTime 					Time when the flow transmission started
  *	@param 	const char*	prettySourceAddress			Pretty format of the source address (usefull for debuging and outputs, minimizes requests for strcpy())
  *	@param 	const char* prettyDestinationAddress	Pretty format of the destination address (debuging and outputs, optimalization)
  *	@param 	uint8_t		typeOfService				Type of service represented by 8-bit integer value (data type corresponding to the real iphdr->ip_tos data type)
  */
void createExpiredFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, uint8_t typeOfService)
{
	// Setting values for the new flow
	T_Flows newFlow;
	newFlow.sourceAddress 				=		sourceAddress;
	newFlow.destinationAddress 			=		destinationAddress;
	newFlow.sourcePort 					=		sourcePort;
	newFlow.destinationPort 			=		destinationPort;
	newFlow.protocolType 				=		protocolType;
	newFlow.bytesTransfered 			=		bytesTransfered;
	newFlow.flowExpired 				=		true;
	newFlow.packetCount++;
	

	// Startime + last packet arrival values
	newFlow.startTime.tv_sec 			=		startTime.tv_sec;
	newFlow.startTime.tv_usec 			=		startTime.tv_usec;
	newFlow.lastPacketArrival.tv_sec 	=		startTime.tv_sec;
	newFlow.lastPacketArrival.tv_usec 	=		startTime.tv_usec;

	// It comes in handy to have pretty source & destination addresses (no need for additional inet_ntoa() calls with unneccessary string copying)
	newFlow.prettySourceAddress 		=		prettySourceAddress;
	newFlow.prettyDestinationAddress 	=		prettyDestinationAddress;


	
	expiredFlows.push_back(newFlow);	// Finally adding it to expiredFlows vector
	totalFlowCount++;					// & increasing total flow counter
}


/**
  * Creates TCPFlow with all its requisities
  * @param	in_addr		sourceAddress 				Source address of the flow
  *	@param	in_addr		destinationAddress 			Destination address of the flow
  * @param 	u_short		sourcePort					Source port of the flow
  *	@param 	u_short 	destinationPort				Destination port of the flow
  * @param 	u_int		protocolType				Protocol type of the flow (TCP = 6)
  *	@param 	u_int		bytesTransfered				Initial number of bytes that were transfered within this flow
  *	@param 	timeval		startTime 					Time when the flow transmission started
  *	@param 	const char*	prettySourceAddress			Pretty format of the source address (usefull for debuging and outputs, minimizes requests for strcpy())
  *	@param 	const char* prettyDestinationAddress	Pretty format of the destination address (debuging and outputs, optimalization)
  * @param 	bitset<8> 	tcpFlags 					All the TCPFlags (ACK, FIN, RST are important)
  *	@param 	uint8_t		typeOfService				Type of service represented by 8-bit integer value (data type corresponding to the real iphdr->ip_tos data type)
  * @param 	uint8_t 	flagsForCollector 			Flags passed as the collector requires them (there is no easy way to convert it from the bitset<8> tcpFlags)
  */
void createTCPFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, bitset<8> tcpFlags, uint8_t typeOfService, uint8_t tcpFlagsForCollector)
{
	// Initialization of new TCP flow
	T_Flows newFlow;
	newFlow.sourceAddress 				= 		sourceAddress;
	newFlow.destinationAddress 			= 		destinationAddress;
	newFlow.sourcePort 					= 		sourcePort;
	newFlow.destinationPort 			= 		destinationPort;
	newFlow.protocolType 				= 		protocolType;
	newFlow.bytesTransfered 			= 		bytesTransfered;
	newFlow.flowExpired 				= 		false;
	newFlow.packetCount++;
	

	// Startime + last packet arrival
	newFlow.startTime.tv_sec 			=		startTime.tv_sec;
	newFlow.startTime.tv_usec 			= 		startTime.tv_usec;
	newFlow.lastPacketArrival.tv_sec 	= 		startTime.tv_sec;
	newFlow.lastPacketArrival.tv_usec 	= 		startTime.tv_usec;

	// For debugging purposes, I use pretty source address to be able to compare what am I actually putting in
	newFlow.prettySourceAddress 		= 		prettySourceAddress;
	newFlow.prettyDestinationAddress 	= 		prettyDestinationAddress;

	// Additional information for the flow
	newFlow.typeOfService 				= 		typeOfService;
	newFlow.tcpFlagsForCollector 		|= 		tcpFlagsForCollector;	// Cumulative OR calculation
	newFlow.tcpFlags = tcpFlags;

	// Calculate cummulative OR for TCPFLAGS


	// Check on FIN || RST
	if(tcpFlags.test(0) || tcpFlags.test(2))
	{
		// In case they are accepted, flow is expired instantly
		newFlow.finArrived = true;
		newFlow.flowExpired = true;
		expiredFlows.push_back(newFlow);
	}
	else
	{
		processedFlows.push_back(newFlow);		// Otherwise putting the flow to processedFlows (active)
	}	

	totalFlowCount++;	// And increasal of total flow count
}


/**
  *	Updates TCP flow with new values when existing active (processedFlow) is encountered - otherwise sets createNewFlow pointer to true
  * @param 	bitset<8> 		tcpFlags 			TCPFlags (ACK, FIN, RST are important)
  *	@param 	pcap_pkthdr 	header 				Packet header used for packet information gathering
  *	@param 	in_addr 		sourceAddress 		Source address to identify flow
  * @param 	in_addr 		destinationAddress 	Destination address to indentify flow
  * @param 	u_short 		sourcePort 			Source port to identify flow
  * @param 	u_short 		destinationPort 	Destination port to identify flow
  *	@param 	int 			protocolType 		Protocol type to identify flow
  * @param 	bool 			*createNewFlow 		Pointer evaluating whether creation of new flow is required
  * @param 	uint8_t 	flagsForCollector 			Flags passed as the collector requires them (there is no easy way to convert it from the bitset<8> tcpFlags)
  */
void handleFlowUpdate(bitset<8> tcpFlags, struct pcap_pkthdr header, in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, int protocolType, bool *createNewFlow, uint8_t tcpFlagsForCollector)
{
	// Looping through processedFlows
	for(vector<T_Flows>::iterator it = processedFlows.begin(); it != processedFlows.end(); ++it)
	{
		// Check whether this exact flow exists within processedFlows
		if(	
			it->destinationAddress.s_addr 	== 	destinationAddress.s_addr && 
			it->sourceAddress.s_addr 		== 	sourceAddress.s_addr && 
			it->destinationPort 			== 	destinationPort && 
			it->protocolType 				== 	protocolType &&
			it->sourcePort 					== 	sourcePort										
	   	  )
			{
				// Based on that, update flow metrics
				it->bytesTransfered 			= 	it->bytesTransfered + header.len;
				it->packetCount 				= 	it->packetCount+1;
				it->lastPacketArrival.tv_sec 	= 	header.ts.tv_sec;
				it->lastPacketArrival.tv_usec 	= 	header.ts.tv_usec;
				it->tcpFlagsForCollector		|=	tcpFlagsForCollector;				// Cumulative OR calculation
			

				// FIN flag reached - this flow expires right now
				if(tcpFlags.test(0))
				{
					it->finArrived 		= 	true;
					it->flowExpired 	= 	true;

					expiredFlows.push_back(*it);	// Moving to expiredFlows
					processedFlows.erase(it);		// Removing from processedFlows
					it--;							// Adjusting pointer accordingly 
				}
				else if(tcpFlags.test(2))
				{
					// FINish current flow
					it->finArrived 		= 	true;
					it->flowExpired 	= 	true;

					expiredFlows.push_back(*it);	// Moving to expiredFlows
					processedFlows.erase(it);		// Removing from processedFlows
					it--;							// Adjusting pointer accordingly 
				}
				else
				{
					// Do nothing
					// Debug: Print out updated data
				}

				*createNewFlow = false;		// Setting createNewFlow pointer to false (no need to create new when the old one was updated)
				break;						// Breaking the loop (optimalization)
		}
	}
}


/**
  *	Expires the TCP connection that has been inactive for the longest period of time
  * @param long currentTimeSec 		Seconds since 1970 (its "currency" is relative to the time of packet that is being processed at the moment)
  * @param long currentTimeMiliSec	Miliseconds since 1960 (its "currency" is relative to the time of packet that is being processed at the moment)
  */
void expireLongestInactiveConnection(long currentTimeSec, long currentTimeMiliSec)
{
	if(processedFlows.size() > 0)
	{

		// Initialization 
		vector<T_Flows>::iterator 		auxIter;
		
		long oldestFoundSec 		=	currentTimeSec;
		long oldestFoundMSec		=	currentTimeMiliSec;
		
		bool foundOldest 			= 	false;

		// Looping vector of processedFlows & searching for the longest inactive connection
		vector<T_Flows>::iterator it2;
		for(it2 = processedFlows.begin(); it2 != processedFlows.end(); ++it2)
		{
			// Searching for the long-time inactive connection
			if(doubleTime(it2->lastPacketArrival.tv_sec, it2->lastPacketArrival.tv_usec) <= doubleTime(oldestFoundSec, oldestFoundMSec))
			{
				oldestFoundSec  	= 	it2->lastPacketArrival.tv_sec;
				oldestFoundMSec 	=	it2->lastPacketArrival.tv_usec;
				auxIter 			= 	it2;
				foundOldest			= 	true;

			}
		}

		// Move found connection to expiredFlows, remove it from the processedFlows (active flows)
		expiredFlows.push_back(*auxIter);
		processedFlows.erase(auxIter);
	}
}


/**
  *	Exports flows stored in expiredFlows to collector
  */
void exportFlows()
{

	// Initial calculation of how many packets need to be exported 
	int packetsToExport;
	double packetDivision = ceil(expiredFlows.size() / 30.0);
	packetsToExport = (int) packetDivision;
	
	// Loop through packets to export & create its bodie and headers
	for(int packetNumber = 0; packetNumber < packetsToExport; packetNumber++)
	{
		// Structure of outgoing packet
		struct outgoingPacket outPacket;


			// Two ways to end the loop, either you run out of expiredFlows or you live long enough to see your flowsPacked limit being exceeded.
			int flowsPacked = 0;
			for(vector<T_Flows>::iterator flow = expiredFlows.begin(); (flow != expiredFlows.end() && flowsPacked != 30 ); ++flow)
			{
				// Packet body creation
				uint32_t auxLastTime = (uint32_t)  ((doubleTime(flow->lastPacketArrival.tv_sec, flow->lastPacketArrival.tv_usec) - doubleTime(firstPacketTimeSec, firstPacketTimeMSec))*1000);	
				uint32_t auxFirstTime = (uint32_t) ((doubleTime(flow->startTime.tv_sec, flow->startTime.tv_usec) - doubleTime(firstPacketTimeSec, firstPacketTimeMSec))*1000);

				outPacket.pBody[flowsPacked].srcaddr 	=	flow->sourceAddress;								// Source address
				outPacket.pBody[flowsPacked].dstaddr 	=	flow->destinationAddress;							// Destination address
				outPacket.pBody[flowsPacked].dPkts	 	=	htonl(flow->packetCount);							// Packet count
				outPacket.pBody[flowsPacked].dOctets 	=	htonl(flow->bytesTransfered);						// Bytes transfered (Octet == Byte, caused by historic inconsistency)
				outPacket.pBody[flowsPacked].First 		=	htonl(auxFirstTime);
				outPacket.pBody[flowsPacked].Last 		=	htonl(auxLastTime);
				outPacket.pBody[flowsPacked].srcport  	=	htons(flow->sourcePort);							// Source port
				outPacket.pBody[flowsPacked].dstport  	=	htons(flow->destinationPort);						// Destination port
				outPacket.pBody[flowsPacked].tcp_flags 	=	flow->tcpFlagsForCollector;							// TCP Flags
				outPacket.pBody[flowsPacked].prot 		=	flow->protocolType;									// Protocol type (UDP/IGMP/ICMP/TCP)
				outPacket.pBody[flowsPacked].tos 		=	flow->typeOfService;								// Type of service

					// As for the hton*() functions - they are used accordingly to data-type used for the given property
				
				expiredFlows.erase(flow);		// After I pack it to the packets, I also remove it from the expiredFlows
				flow--;							// It is important to adjust the pointer, otherwise unexpected behavior may occur

				// Increase the counter of packed packets
				flowsPacked++;
			}

			
			// Packet header creation			
			uint32_t auxSysUpTime=(uint32_t) ((double)(doubleTime(currentPacketTimeSec, currentPacketTimeMSec) - doubleTime(firstPacketTimeSec, firstPacketTimeMSec))*1000);

			outPacket.pHeader.count 		=	htons(flowsPacked);						// Flows packed to this packet
			outPacket.pHeader.sysUpTime 	=	htonl(auxSysUpTime);					// SysUpTime
			outPacket.pHeader.unix_secs 	=	htonl(currentPacketTimeSec);			// unix_secs
			outPacket.pHeader.unix_nsecs 	=	htonl((currentPacketTimeMSec/1000));	// unix_nsecs
			outPacket.pHeader.flow_sequence	=	htonl(totalFlowCount);					// Flow sequence
			

			// Header completed, now send

			// CODE TAKEN FROM Old IPK project START
			
			int 		comSock;		// Communication socket
			sockaddr_in	RecvAddr;		// Server address information

			// Socket creation
			if((comSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
			{
				cerr << "Socket creation failed!" << endl;
			}

			// Memory reset to zeros for RecvAddr (good practice)
			memset(&RecvAddr, 0, sizeof(RecvAddr));		


			// Basically: RecvAddr.sin_addr = Parameters.collectorAddress; but via allowed constructions
			inet_pton(AF_INET, Parameters.collectorAddress.c_str(), &(RecvAddr.sin_addr));
			
			RecvAddr.sin_port	=	htons(Parameters.port);
			RecvAddr.sin_family	=	AF_INET;

			int packetSizeInTotal = (flowsPacked*sizeof(struct packetBody)) + sizeof(struct packetHeader);		// Calculated packet size (packet_header_size + number_of_records*packet_record_size)

			// Sending a packet
			if((sendto(comSock, &outPacket, packetSizeInTotal, 0, (const sockaddr *) &RecvAddr, sizeof(RecvAddr))) == -1)
			{
				cerr << "Packet sending failed!" << endl;
			}
			
			// CODE TAKEN FROM Old IPK project END
	}
		
	// Clearing expiredFlows vector (I just exported all of it, removal is in place)
	expiredFlows.clear();
}


/**
  *	Expires flows (moves them from processedFlows to expiredFlows)
  */
void expireFlows()
{
	// Simple loop through all the flows stored in processedFlows vector
	for(vector<T_Flows>::iterator flow = processedFlows.begin(); flow != processedFlows.end(); ++flow)
	{
		expiredFlows.push_back(*flow);	
	}
	
	// After transaction, clears the original vector
	processedFlows.clear();
}


/**
  *	Returns double value of the time consisted of standard timeval elements 
  *	@param 	long 	timeSec 	Timeval element containing seconds since 1970
  *	@param 	long 	timeMSec 	Timeval element containing microseconds since 1970
  */
double doubleTime(long timeSec, long timeMSec)
{

	// Inits
	stringstream 		sstm;
	string results;

	string smsec 	= 	to_string(timeMSec);	// String representation of microseconds
	string aux 		= 	"0.";					// Auxiliary string pretending to be the real part of the number
	
	// String are concatenated to stringstream sstm
	sstm << aux;

	// Loop ensures microseconds are represented properly (leading zeros)
	for(int i = 0; i < (6-smsec.size()); i++)
	{
		sstm << "0";
	}

	// Concatenation & result forging
	sstm << timeMSec;
	results = sstm.str();

	// Conversion back to double & returning value
	double realMsec  = stod(results);
	return (double) (timeSec + realMsec);
}


/**
  *	Handles addresses that may come from -c, sets it to Parameters structure
  *	@param 	string 	sArg containing one of the following: xxx.xxx.xxx.xxx:xxx, xxx.xxx.xxx.xxx, samplehostname, samplehostname:xxx
  */
void setCollectorHostParameters(string sArg)
{
	// String separation
	if(sArg.find(":") != string::npos)
	{
		// BASED ON CODE FROM STACK OVERFLOW: http://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c START
		size_t pos = 0;
		string delimeter = ":";
		string token;
		while ((pos = sArg.find(delimeter)) != std::string::npos) 
		{
    		token = sArg.substr(0, pos);
  		
    		Parameters.collectorAddress = token;
       		
    		sArg.erase(0, pos + delimeter.length());
		}
		// BASED ON CODE FROM STACK OVERFLOW: http://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c END
		Parameters.port = stoi(sArg);
	}
	else
	{
		Parameters.collectorAddress = sArg;
	}
}


/**
  *	This function initializes parameters to default values (given by task-assignment)
  */
void ParamInit()
{
	Parameters.inputFile = "-";
	Parameters.collectorAddress = "127.0.0.1:2055";	// TODO: Rewrite this to work with collectorAddress & port
	Parameters.interval = 300;
	Parameters.timeout = 300;
	Parameters.maxFlows = 50;
}


/**
  *	Test method for ParamInit method. Serves debug purposes only.
  */
void testParamInit(T_Parameters params)
{
	cout << "Given: " << params.inputFile 			<< endl << "Expected: " << defaultValue_input 				<< endl << "==========" << endl;
	cout << "Given: " << params.collectorAddress 	<< endl << "Expected: " << defaultValue_collectorAddress 	<< endl << "==========" << endl;
	cout << "Given: " << params.interval 			<< endl << "Expected: " << defaultValue_interval 			<< endl << "==========" << endl;
	cout << "Given: " << params.timeout 			<< endl << "Expected: " << defaultValue_timeout 			<< endl << "==========" << endl;
	cout << "Given: " << params.maxFlows 			<< endl << "Expected: " << defaultValue_maxflows 			<< endl << "==========" << endl;
}