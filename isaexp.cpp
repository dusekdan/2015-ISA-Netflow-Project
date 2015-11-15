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
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>	// inet_ntoa
#include <sys/socket.h>
#include "isaexp.h"

// Only namespace truely required
using namespace std;


// Basic global structures and vectors used across this program
T_Parameters Parameters;
vector<T_Flows> processedFlows;
vector<T_Flows> expiredFlows;


int main(int argc, char * argv[])
{
	
	// Set default parameters for program
	ParamInit();

	// Auxiliary variables for parameter handling
	int goarg = 0;
	int index;

	// Processes variables
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


	// PCAP file opening
	
	// Auxiliary variables and structures for file reading and opening
	
	char 	pcapErrorBuffer[PCAP_ERRBUF_SIZE];	// String for Error that may occur while reading pcap file
	
	const u_char *packet;						// Pointer in memory to packet
	struct pcap_pkthdr header;					// Paket header according to pcap representation
	struct ether_header *eptr;					// Pointer to ethernet header
	pcap_t *handle; 							// Handle to file (and on online-exporter it would be device) which the pcap stream is coming from
	
	// Structures for different headers
	struct ip *my_ip;
	struct tcphdr *my_tcp;
	struct udphdr *my_udp;
	struct icmphdr *my_icmp;
	struct igmphdr *my_igmp;

	// Counters for each supported protocol
	int tcppacket = 0;
	int udppacket = 0;
	int igmppacket = 0;
	int arppacket = 0;
	int icmppacket = 0;
	int other = 0;

	// New flow record variables TODO: Clarify this section
	const char *prettySourceAddress, *prettyDestinationAddress;
	in_addr sourceAddress, destinationAddress;
	u_short sourcePort, destinationPort;
	u_int bytesTransfered;
	int protocolType;
	const char* auxBuff;

	// Offline opening of the file, requires C-string representation of the input stream (xxx.c_str())

	handle = pcap_open_offline(Parameters.inputFile.c_str(), pcapErrorBuffer);		// On error fills the pcapErrorBuffer with message 
		if(handle == NULL)		
		{
			// Immediate check if the operation was successful 
			cerr << "Error occured: " << pcapErrorBuffer << endl;
			exit(1);
		}

	// Read PCAP file

	// Init packet counter & loop through packets
	int packetCount = 0;
	while((packet = pcap_next(handle, &header)) != NULL)
	{


		eptr = (struct ether_header *) packet;		// Contains ethernet header (used for switch packet types between ethernet/arp/else)
		

		my_ip = (struct ip*) (packet+14);		

	
		if(ntohs(eptr->ether_type) == ETHERTYPE_IP)
		{
			switch(my_ip->ip_p)
			{
				case protoNumber_ICMP:
					icmppacket++;
				break;

				case protoNumber_IGMP:
					igmppacket++;
				break;

				case protoNumber_TCP:
					tcppacket++;

					// Handle to access tcp data
					my_tcp = (struct tcphdr *) (my_ip + my_ip->ip_hl*4);

					// 5 values identifying flow
					sourceAddress		= (in_addr) my_ip->ip_src;
					destinationAddress 	= my_ip->ip_dst; 
					sourcePort 			= (u_short) my_tcp->th_sport;
					destinationPort 	= (u_short) my_tcp->th_dport;
					protocolType		= protoNumber_TCP;
					bytesTransfered		= header.len;

					// Pretty debug names
					auxBuff = inet_ntoa(my_ip->ip_src);
					prettySourceAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);
					auxBuff = inet_ntoa(my_ip->ip_dst);
					prettyDestinationAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

					//Check flow (not) exists
					if(processedFlows.empty())
					{
						createFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress);
						cout << "* First record added to processedFlows (currently " << processedFlows.size() << ")" << endl;
					}
					else
					{
						// Initialize on true, set to false if flow exists (and is discovered by for loop)
						bool createNewFlow = true;

						for(vector<T_Flows>::iterator it = processedFlows.begin(); it != processedFlows.end(); ++it)
						{
							// Existing flow identification
							if(it->sourceAddress.s_addr == sourceAddress.s_addr && it->destinationAddress.s_addr == destinationAddress.s_addr && it->sourcePort == sourcePort && it->destinationPort == destinationPort && it->protocolType == protocolType)
							{
								// Update existing flow: bytesTransfered, packetCount, lastPacketArrival (both seconds & useconds)
								it->bytesTransfered 			= 	it->bytesTransfered+bytesTransfered;
								it->packetCount 				= 	it->packetCount+1;
								it->lastPacketArrival.tv_sec 	= 	header.ts.tv_sec;
								it->lastPacketArrival.tv_usec 	= 	header.ts.tv_usec;

								cout << "* Flow record exists, updated existing (currently " << processedFlows.size() << ")"  << endl;
								cout << "\t Time from header: " <<  header.ts.tv_sec << ":" << header.ts.tv_usec << endl;
								cout << "\t Time in record  : " << it->lastPacketArrival.tv_sec << ":" << it->lastPacketArrival.tv_usec << endl;

								// Do not create another flow record, terminate the for loop (optimalization)
								createNewFlow = false;
								break;
							}
						}

						// Condition is true when no record for the tuple of sourceAddress, destinationAddress, sourcePort, destinationPort & protocolType is found
						if(createNewFlow)
						{
								// Creates flow record for the current tuple
								createFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress);
								
								// Set need for creating new flow back to false
								createNewFlow = false;
								
								// TODO: Debug only, remove this
								cout << "* New record created in processedFlows (currently " << processedFlows.size() << ")" << endl;
						}

					}


				break;

				case protoNumber_UDP:
					udppacket++;

					// Handle to access udp data
					my_udp = (struct udphdr *) (my_ip + my_ip->ip_hl*4);

					// 5 values identifying flow
					sourceAddress		= 	(in_addr) my_ip->ip_src;
					destinationAddress 	= 	(in_addr) my_ip->ip_dst; 
					sourcePort 			= 	(u_short) my_udp->uh_sport;
					destinationPort 	= 	(u_short) my_udp->uh_dport;
					protocolType		= 	protoNumber_UDP;	
					bytesTransfered		= 	header.len;

					// Pretty debug names
					auxBuff = inet_ntoa(my_ip->ip_src);
					prettySourceAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);
					auxBuff = inet_ntoa(my_ip->ip_dst);
					prettyDestinationAddress = strcpy(new char[strlen(auxBuff)+1], auxBuff);

					// Create expired flow
					createFlow(sourceAddress, destinationAddress, sourcePort, destinationPort, protocolType, bytesTransfered, header.ts, prettySourceAddress, prettyDestinationAddress);
				break;
			}
		}
		else
		{
			other++;
		}

	}

	cout << "Total stats: \n \tIGMP: " << igmppacket << "x\n\tTCP: " << tcppacket << "x\n\tUDP: " << udppacket << "x\n\tARP: " << arppacket << "x\n\tICMP: " << icmppacket <<"x\n\tOthers: " << other << "x\n\t"  << endl;
}






void createFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress)
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

	// UDP & ICMP & IGMP goes to expired state instantly
	if(protocolType == 17 || protocolType == 1 || protocolType == 2)
	{
		// Expired property set to expired
		newFlow.flowExpired = true;
		expiredFlows.push_back(newFlow);
	}
	else
	{
		processedFlows.push_back(newFlow);
	}


	cout << "PT:" << protocolType << "|" << newFlow.prettySourceAddress << ":" << newFlow.sourcePort << "->" << newFlow.prettyDestinationAddress << ":" << newFlow.destinationPort << "|" << "Sec:" << newFlow.startTime.tv_sec << "~Usec:" << newFlow.startTime.tv_usec << endl;

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