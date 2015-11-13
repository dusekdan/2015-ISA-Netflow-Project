#include <iostream>
#include <pcap.h>
#include <getopt.h>
#include <cstdlib>	// atoi and stuff

#define optarg_no 0
#define optarg_required 1
#define optarg_optinal 2

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

T_Parameters Parameters;

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

//string collectorAddress = "127.0.0.1:2055";

int main(int argc, char * argv[])
{

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

	ParamInit();
	testParamInit(Parameters);

	//cout << "Hello world!\n" << collectorAddress << endl;
	return 0;
}