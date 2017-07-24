#include "ScvpScriptGenerator.h"

//STL includes
#include <iostream>

//Boost includes
#include "boost/program_options.hpp"

//namespaces
using namespace boost;
using namespace std;
namespace po = boost::program_options;

//------------------------------------------------------------------------
// Miscellaneous functions
//------------------------------------------------------------------------
//options parsing and usage display functions
void ShowUsage();
bool ParseOptions(int argc, const char **argv, po::variables_map &vm, std::vector<std::string>& wantBacks);

void LoadPkits(const std::string& folder);
void output_csv();
void output_script_lightweight_pkits(const std::string& logging_conf, const std::string& output_folder, const std::string& pkits_folder, enum PKITS_Edition pe, std::vector<std::string>& wantBacks);
void output_script_longterm_pkits(const std::string& logging_conf, const std::string& output_folder, const std::string& pkits_folder, enum PKITS_Edition pe, std::vector<std::string>& wantBacks);
void output_script_batch_pkits(const std::string& logging_conf, const std::string& output_folder, const std::string& pkits_folder, enum PKITS_Edition pe, std::vector<std::string>& wantBacks);

void output_script_lightweight_pdts(const std::string& logging_conf, const std::string& output_folder, const std::string& pdts_folder, std::vector<std::string>& wantBacks);
void output_script_longterm_pdts(const std::string& logging_conf, const std::string& output_folder, const std::string& pdts_folder, std::vector<std::string>& wantBacks);
void output_script_batch_pdts(const std::string& logging_conf, const std::string& output_folder, const std::string& pdts_folder, std::vector<std::string>& wantBacks);

void output_script_lightweight_mfpki(const std::string& logging_conf, const std::string& output_folder, const std::string& mfpki_folder, std::vector<std::string>& wantBacks, const std::string& mfpki_ta);
void output_script_longterm_mfpki(const std::string& logging_conf, const std::string& output_folder, const std::string& mfpki_folder, std::vector<std::string>& wantBacks, const std::string& mfpki_ta);
void output_script_batch_mfpki(const std::string& logging_conf, const std::string& output_folder, const std::string& mfpki_folder, std::vector<std::string>& wantBacks, const std::string& mfpki_ta);

/**

 @return 0 upon success, non-zero upon failure.
 */
int main (int argc, const char * argv[])
{
    po::variables_map vm;   //container for variables parsed from the command line
    std::vector<std::string> wantBacks;
    try
    {
        if(!ParseOptions(argc, argv, vm, wantBacks))
		{
            return 1; //any error message is written within ParseOptions
		}

    }
    catch (std::exception& e)
    {
        cout << "Error parsing command line arguments";
		if(e.what())
			cout << ": " << e.what();
		cout << std::endl;
        return 1;
    }

    /*
     //Each of these MUST be specified
     ("logging_conf,l",po::value<string>(),"Logging configuration to support report generation")
     ("output_folder",po::value<string>(),"Folder to receive generated scripts")
     
     //Only one of these will be used (first one found in the order given here)
     ("pkits_2048_folder",po::value<string>(),"Folder containing PKITS 2048 edition")
     ("pkits_4096_folder",po::value<string>(),"Folder containing PKITS 4096 edition")
     ("pkits_p256_folder",po::value<string>(),"Folder containing PKITS p256 edition")
     ("pkits_p384_folder",po::value<string>(),"Folder containing PKITS p384 edition")
     ("pdts_folder",po::value<string>(),"Folder containing PDTS edition")
     ("mfpki_folder",po::value<string>(),"Folder containing MFPKI edition")
     
     //This MAY be specified (and is picked up and used above if so)
     ("logging,l",po::value<string>(),"Logging configuration for ScvpScriptGenerator logging purposes")
    */
    std::string logging_conf, output_folder;
    if (0 != vm.count("logging_conf"))
    {
        logging_conf = vm["logging_conf"].as< std::string >();
    }
    //else
    //{
    //    std::cout << "ERROR: the logging_conf parameter MUST be specified" << std::endl;
    //    return 0;
    //}
    if (0 != vm.count("output_folder"))
    {
        output_folder = vm["output_folder"].as< std::string >();
    }
    else
    {
        std::cout << "ERROR: the output_folder parameter MUST be specified" << std::endl;
        return 0;
    }
    
    if(1 < (vm.count("pkits_2048_folder") + vm.count("pkits_4096_folder") + vm.count("pkits_p256_folder") + vm.count("pkits_p384_folder") + vm.count("pdts_folder") + vm.count("mfpki_folder")))
    {
        std::cout << "ERROR: only one of pkits_2048_folder, pkits_4096_folder, pkits_p256_folder, pkits_p384_folder, pdts_folder or mfpki_folder may be specified." << std::endl;
        return 0;
    }

    if(0 == (vm.count("pkits_2048_folder") + vm.count("pkits_4096_folder") + vm.count("pkits_p256_folder") + vm.count("pkits_p384_folder") + vm.count("pdts_folder") + vm.count("mfpki_folder")))
    {
        std::cout << "ERROR: one of pkits_2048_folder, pkits_4096_folder, pkits_p256_folder, pkits_p384_folder, pdts_folder or mfpki_folder must be specified." << std::endl;
        return 0;
    }

    if(0 != vm.count("pkits_2048_folder"))
    {
        std::string pkits_folder =vm["pkits_2048_folder"].as< std::string >();
        LoadPkits(pkits_folder);
        output_script_lightweight_pkits(logging_conf, output_folder, pkits_folder, PKITS_2048, wantBacks);
        output_script_longterm_pkits(logging_conf, output_folder, pkits_folder, PKITS_2048, wantBacks);
        output_script_batch_pkits(logging_conf, output_folder, pkits_folder, PKITS_2048, wantBacks);
    }
    else if(0 != vm.count("pkits_4096_folder"))
    {
        std::string pkits_folder =vm["pkits_4096_folder"].as< std::string >();
        LoadPkits(pkits_folder);
        output_script_lightweight_pkits(logging_conf, output_folder, pkits_folder, PKITS_4096, wantBacks);
        output_script_longterm_pkits(logging_conf, output_folder, pkits_folder, PKITS_4096, wantBacks);
        output_script_batch_pkits(logging_conf, output_folder, pkits_folder, PKITS_4096, wantBacks);
    }
    else if(0 != vm.count("pkits_p256_folder"))
    {
        std::string pkits_folder =vm["pkits_p256_folder"].as< std::string >();
        LoadPkits(pkits_folder);
        output_script_lightweight_pkits(logging_conf, output_folder, pkits_folder, PKITS_P256, wantBacks);
        output_script_longterm_pkits(logging_conf, output_folder, pkits_folder, PKITS_P256, wantBacks);
        output_script_batch_pkits(logging_conf, output_folder, pkits_folder, PKITS_P256, wantBacks);
    }
    else if(0 != vm.count("pkits_p384_folder"))
    {
        std::string pkits_folder =vm["pkits_p384_folder"].as< std::string >();
        LoadPkits(pkits_folder);
        output_script_lightweight_pkits(logging_conf, output_folder, pkits_folder, PKITS_P384, wantBacks);
        output_script_longterm_pkits(logging_conf, output_folder, pkits_folder, PKITS_P384, wantBacks);
        output_script_batch_pkits(logging_conf, output_folder, pkits_folder, PKITS_P384, wantBacks);
    }
    else if(0 != vm.count("pdts_folder"))
    {
        std::string pdts_folder = vm["pdts_folder"].as< std::string >();
        output_script_lightweight_pdts(logging_conf, output_folder, pdts_folder, wantBacks);
        output_script_longterm_pdts(logging_conf, output_folder, pdts_folder, wantBacks);
        output_script_batch_pdts(logging_conf, output_folder, pdts_folder, wantBacks);
    }
    else if(0 != vm.count("mfpki_folder"))
    {
        std::string mfpki_ta;
        if (0 != vm.count("mfpki_ta"))
        {
            mfpki_ta = vm["mfpki_ta"].as< std::string >();
        }
        else
        {
            std::cout << "ERROR: the mfpki_ta parameter MUST be specified when targeting the MFPKI" << std::endl;
            return 0;
        }
        std::string mfpki_folder = vm["mfpki_folder"].as< std::string >();
        output_script_lightweight_mfpki(logging_conf, output_folder, mfpki_folder, wantBacks, mfpki_ta);
        output_script_longterm_mfpki(logging_conf, output_folder, mfpki_folder, wantBacks, mfpki_ta);
        output_script_batch_mfpki(logging_conf, output_folder, mfpki_folder, wantBacks, mfpki_ta);
    }
    
	return 1;
}


//------------------------------------------------------------------------
//options parsing and usage display functions
//------------------------------------------------------------------------
void ShowUsage(po::options_description& options)
{
    cout << "ScvpScriptGenerator v1.0.0 usage" << endl << options << std::endl;
}

/*
 $ java -jar vss.jar -h
 usage: TestProgramSCVPClient [-h] [-u SCVP_URL] [--scvp_profile {lightweight,long-term-record,batch}] [-x {true,false}] [-l LOGGING_CONF] [-c TARGET_CERT] [-b BATCH_FOLDER] [-t [TRUST_ANCHOR [TRUST_ANCHOR ...]]] [-v VALIDATION_POLICY]
 [--wantBacks [{Cert,BestCertPath,RevocationInfo,PublicKeyInfo,AllCertPaths,EeRevocationInfo,CAsRevocationInfo} [{Cert,BestCertPath,RevocationInfo,PublicKeyInfo,AllCertPaths,EeRevocationInfo,CAsRevocationInfo} ...]]]
 [-p [CERTIFICATE_POLICY [CERTIFICATE_POLICY ...]]] [--inhibitAnyPolicy {true,false}] [--inhibitPolicyMapping {true,false}] [--requireExplicitPolicy {true,false}]
 
 Validates a target certificate using a given SCVP server and set of criteria.
 
 optional arguments:
    -h, --help             show this help message and exit
 
 Basic Logistics:
    --scvp_profile {lightweight,long-term-record,batch}
        Name of SCVP profile. (default: lightweight)
    -x {true,false}, --expectSuccess {true,false}
        Boolean value indicating whether success is expected. Applies to either --target_cert or all certs in --batch_folder (default: true)
    -l LOGGING_CONF, --logging_conf LOGGING_CONF
        Full path and filename of log4j configuration file.
 
 Target Certificate Details:
    -c TARGET_CERT, --target_cert TARGET_CERT
        Full path and filename of certificate to validate. Not used when --scvp_profile is set to batch, required otherwise.
    -b BATCH_FOLDER, --batch_folder BATCH_FOLDER
        Full path of folder containing binary DER encoded certificates to specify as targets in a single CVRequest. Required when --scvp_profile is set to batch and omitted otherwise.
    -t [TRUST_ANCHOR [TRUST_ANCHOR ...]], --trust_anchor [TRUST_ANCHOR [TRUST_ANCHOR ...]]
        Full path and filename to file containing binary DER encoded certificate to use as a trust anchor. Omitted from request by default.
 
 SCVP Request Details:
    -v VALIDATION_POLICY, --validation_policy VALIDATION_POLICY
        Validation policy or policies to include in the SCVP request. Object identifiers are expressed in dot notation form: 1.2.3.4.5. (default: 1.3.6.1.5.5.7.19.1)
    --wantBacks [{Cert,BestCertPath,RevocationInfo,PublicKeyInfo,AllCertPaths,EeRevocationInfo,CAsRevocationInfo} [{Cert,BestCertPath,RevocationInfo,PublicKeyInfo,AllCertPaths,EeRevocationInfo,CAsRevocationInfo} ...]]
        Want back values to include in as CVRequest.query.wantBack. (default: [BestCertPath])
 
 Certification Path Validation Algorithm Inputs:
    -p [CERTIFICATE_POLICY [CERTIFICATE_POLICY ...]], --certificate_policy [CERTIFICATE_POLICY [CERTIFICATE_POLICY ...]]
        Certificate policy or policies to use as CVRequest.query.wantBack. Object identifiers are expressed in dot notation form: 1.2.3.4.5 2.3.4.5.6 etc. Omitted from request by default.
    --inhibitAnyPolicy {true,false}
        Boolean value to use as CVRequest.query.validationPolicy.inhibitAnyPolicy. Omitted from request by default.
    --inhibitPolicyMapping {true,false}
        Boolean value to use as CVRequest.query.validationPolicy.inhibitPolicyMapping. Omitted from request by default.
    --requireExplicitPolicy {true,false}
        Boolean value to use as CVRequest.query.validationPolicy.requireExplicitPolicy. Omitted from request by default.
*/

/*
    -l LOGGING_CONF, --logging_conf LOGGING_CONF
        Full path and filename of log4j configuration file.

    --pkits_2048_folder PKITS_2048_FOLDER
        Full path of folder containing PKITS 2048 certificates.
    --pkits_4096_folder PKITS_4096_FOLDER
        Full path of folder containing PKITS 4096 certificates.
    --pkits_p256_folder PKITS_p256_FOLDER
        Full path of folder containing PKITS p256 certificates.
    --pkits_p384_folder PKITS_p384_FOLDER
        Full path of folder containing PKITS p384 certificates.
    --pdts_folder PKITS_p384_FOLDER
        Full path of folder containing PDTS certificates.
    --mfpki_folder MFPKI_FOLDER
        Full path of folder containing MFPKI certificates.
 
    -p OUTPUT_FOLDER, --output_folder OUTPUT_FOLDER
        Full path of folder to receive generated scripts.
 */
/*
    Generated scripts:
 
    Some scripts will feature a few hundred lines (like each PKITS edition for Lightweight and Long-term). Some scripts will feature just a line or two (like
    MFPKI edition for batch). PKITS in batch mode will have one batch per validation policy (with varying number of targets).
 
    Lightweight (12 scripts)
        - PKITS {2048, 4096, p256, p384} using default validation policy with varying parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - PKITS {2048, 4096, p256, p384} using non-default validation policy
        - PDTS using default validation policy with specified parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - PDTS using non-default validation policy
        - MFPKI using default validation policy with specified parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - MPPKI using non-default validation policy

    Batch (12 scripts)
        - PKITS {2048, 4096, p256, p384} using default validation policy with varying parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - PKITS {2048, 4096, p256, p384} using non-default validation policy
        - PDTS using default validation policy with specified parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - PDTS using non-default validation policy
        - MFPKI using default validation policy with specified parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - MPPKI using non-default validation policy

    Long-term (12 scripts)
        - PKITS {2048, 4096, p256, p384} using default validation policy with varying parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - PKITS {2048, 4096, p256, p384} using non-default validation policy
        - PDTS using default validation policy with specified parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - PDTS using non-default validation policy
        - MFPKI using default validation policy with specified parameters (TA, inhibitAnyPolicy, inhibitPolicyMapping, requireExplicitPolicy, userPolicySet)
        - MPPKI using non-default validation policy

 */

bool ParseOptions(
    //![in] Number of arguments in argv
    int argc,
    //![in] Command line arguments
    const char **argv,
    //![out] Variables map populated with the values parsed from the command line
    po::variables_map &vm,
    //![out] Vector to receive wantBack OIDs
    std::vector<std::string>& wantBacks)
{
    po::options_description options;

	// options that should be mentioned to the user in --help go here
	options.add_options()
    ("help,h","Print usage instructions")
    ("logging_conf,l",po::value<string>(),"Logging configuration to support report generation")
    ("pkits_2048_folder",po::value<string>(),"Folder containing PKITS 2048 edition (root of Renamed folder containing 0, 1, 2, etc. folders and all certificates)")
    ("pkits_4096_folder",po::value<string>(),"Folder containing PKITS 4096 edition (root of Renamed folder containing 0, 1, 2, etc. folders and all certificates)")
    ("pkits_p256_folder",po::value<string>(),"Folder containing PKITS p256 edition (root of Renamed folder containing 0, 1, 2, etc. folders and all certificates)")
    ("pkits_p384_folder",po::value<string>(),"Folder containing PKITS p384 edition (root of Renamed folder containing 0, 1, 2, etc. folders and all certificates)")
    ("pdts_folder",po::value<string>(),"Folder containing PDTS edition")
    ("mfpki_folder",po::value<string>(),"Folder containing MFPKI edition")
    ("mfpki_ta",po::value<string>(),"File containing the MFPKI trust anchor")
    ("output_folder",po::value<string>(),"Folder to receive generated scripts")
    ("want_back",po::value<std::vector<std::string> >(&wantBacks),"List of OIDS in dot notation form (i.e., 1.2.3.4.5) to be passes as --wantBacks to the SCVP client")
    ;

	try
    {
		// parse the args and throw the leftovers into input-file
		po::store(po::command_line_parser(argc, argv).options(options).run(), vm);
		po::notify(vm);
	}
    catch(std::exception &e)
    {
        std::cout << e.what() << std::endl;
		throw e;
	}

    if(vm.count("help"))
    {
		ShowUsage(options);
        if(1 == vm.size())
        {
            return false;
        }
    }
    
    if(vm.empty())
    {
        ShowUsage(options);
        return false;
    }
    
    return true;
}


