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

// Protocol number defines
#define protoNumber_ICMP 1
#define protoNumber_IGMP 2
#define protoNumber_TCP 6
#define protoNumber_UDP 17

using namespace std;


// Get opts structure (param handling)
const struct option longopts[] = 
{
	{"input",	optarg_required,	0,	'i'},
    {"collector",	optarg_required,	0,	'c'},
    {"interval", optarg_required, 0, 'I'},
    {"tcp-timeout", optarg_required, 0, 't'},
    {"max-flows", optarg_required, 0, 'm'},
    {0,	0,	0,	0},
};

// Parameters structure
typedef struct
{
	string inputFile;
	string collectorAddress;
	int interval;
	int timeout;
	int maxFlows;
} T_Parameters;

// Flows structure
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
	const char* prettySourceAddress;
	const char* prettyDestinationAddress;
};

void ParamInit();
void testParamInit(T_Parameters params);

void createFlow(in_addr sourceAddress, in_addr destinationAddress, u_short sourcePort, u_short destinationPort, u_int protocolType, u_int bytesTransfered, struct timeval startTime, const char* prettySourceAddress, const char* prettyDestinationAddress);