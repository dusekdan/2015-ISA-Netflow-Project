/**
  *  
  *     ISA Project - Offline netflow probe
  *     @author Daniel Dusek <xdusek21> | 3BIT FIT VUT 2015-2016
  *     
  *     Offline probe designed to read pcap file, aggregate its records to flow
  *     and export those flows to collector. More how to run the program in README.
  *     
  *
  */
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/igmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <iostream>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <cstdlib>
#include <sstream>
#include <pcap.h>
#include <vector>
#include <bitset>
#include <cmath>


// Get opts parameter definitions
#define optarg_no                       0
#define optarg_required                 1
#define optarg_optinal                  2

// Default values for parameters definition
#define defaultValue_collectorAddress "127.0.0.1:2055"
#define defaultValue_input            "stdin"
#define defaultValue_interval         300
#define defaultValue_timeout          300
#define defaultValue_maxflows          50

// Other
#define ETHERNET_HEADER_SIZE          14

// Protocol number defines
#define protoNumber_UDP               17
#define protoNumber_TCP                6
#define protoNumber_IGMP               2
#define protoNumber_ICMP               1 


// Standard namespace to avoid usage of std::
using namespace std;


// PARAMETER HANDLING STRUCTURES
// Structure for getopt function
const struct option longopts[] = 
{
    {   "input",        optarg_required,    0,  'i'     },
    {   "collector",    optarg_required,    0,  'c'     },
    {   "interval",     optarg_required,    0,  'I'     },
    {   "tcp-timeout",  optarg_required,    0,  't'     },
    {   "max-flows",    optarg_required,    0,  'm'     },
    {0,0,0,0},
};

// Structure for parameters itself, initialized to default values
typedef struct
{
    string inputFile;
    string collectorAddress                 =   "127.0.0.1";
    int port                                =   2055;
    int interval;
    int timeout;
    int maxFlows;
} T_Parameters;


// PCAP netflow structure
struct T_Flows 
{
    in_addr     sourceAddress;
    in_addr     destinationAddress;
    u_short     sourcePort;
    u_short     destinationPort;
    u_int       protocolType;
    struct      timeval startTime;
    struct      timeval lastPacketArrival;
    struct      timeval endTime;
    u_int       packetCount                 =   0;
    u_int       bytesTransfered             =   0;
    bool        flowExpired                 =   false;
    bool        finArrived                  =   false;
    uint8_t     typeOfService;
    bitset<8>   tcpFlags;
    uint8_t     tcpFlagsForCollector        =   0;
    const char* prettySourceAddress;
    const char* prettyDestinationAddress;
};

// Packet for collector - header structure
struct packetHeader
{
    uint16_t    version                     =   htons(5);
    uint16_t    count;
    uint32_t    sysUpTime;
    uint32_t    unix_secs;
    uint32_t    unix_nsecs;
    uint32_t    flow_sequence;
    uint8_t     engine_type                 =   0;
    uint8_t     engine_id                   =   0;
    uint16_t    sampling_interval           = htons(0);

};

// Packet for collector - body structure
struct packetBody
{
    in_addr     srcaddr;
    in_addr     dstaddr;
    in_addr     nexthop;
    uint16_t    input                       =   htons(0);
    uint16_t    output                      =   htons(0);
    uint32_t    dPkts;
    uint32_t    dOctets;
    uint32_t    First;
    uint32_t    Last;
    uint16_t    srcport;
    uint16_t    dstport;
    uint8_t     pad1                        =   0;
    uint8_t     tcp_flags;
    uint8_t     prot;
    uint8_t     tos;
    uint16_t    src_as                      =   htons(0);
    uint16_t    dst_as                      =   htons(0);
    uint8_t     src_mask                    =   0;
    uint8_t     dst_mask                    =   0;
    uint16_t    pad2                        =   htons(0);   
};


// Outgoing packet structure itself
struct outgoingPacket
{
    struct packetHeader     pHeader;
    struct packetBody       pBody[30];
};

// Declaration of global variables for active & expired flows + parameters
T_Parameters Parameters;
vector<T_Flows> processedFlows;
vector<T_Flows> expiredFlows;

// Declaration of global variables for time tracking purposes
long firstPacketTimeSec;
long firstPacketTimeMSec;
long currentPacketTimeSec;
long currentPacketTimeMSec;


// Definition of global variable for counting flows in total (set to zero, increased with every loop)
int totalFlowCount              =   0;


// Function declarations
void createExpiredTCPFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, bitset<8> tcpFlags, uint8_t typeOfService, uint8_t tcpFlagsForCollector);
void createTCPFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, bitset<8> tcpFlags, uint8_t typeOfService, uint8_t tcpFlagsForCollector);
void createExpiredFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress, uint8_t typeOfService);
void handleFlowUpdate(bitset<8> tcpFlags, struct pcap_pkthdr header, in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, int protocolType, bool *createNewFlow, uint8_t tcpFlagsForCollector);
void processPacketCheck(struct pcap_pkthdr header, long intervalStartTimeSec, long intervalStartTimeMsec, bool *recordNewInterval);
void expireLongestInactiveConnection(long currentTimeSec, long currentTimeMiliSec);
double doubleTime(long timeSec, long timeMSec);
void setCollectorHostParameters(string sArg);
void testParamInit(T_Parameters params);
void terminationCleanUp(int signal);
void exportFlows();
void expireFlows();
void ParamInit();