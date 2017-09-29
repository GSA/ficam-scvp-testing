---
layout: default
title: Server-based Certificate Validation Protocol (SCVP) Test Program User's Guide
permalink: /scvpuserguide/
---
### Revision History 

Date|Version|Changes|
:---:|:---:|---|
08/11/2017|1.0|Final Publication|

### Table of Contents

* [**1 OVERVIEW**](#1-overview)
* [**2 GSTP COMPONENTS**](#2-gstp-components)
* [2.1 Test SCVP Client](#2.1-test-scvp-client)
* [2.2 Test SCVP Client Scripts and Script Generator](#2.2-test-scvp-client-scripts-and-script-generator)
* [2.3 Test SCVP Client Script Runner](#2.3-test-scvp-client-script-runner)
* [2.4 Test Artifacts](#2.4-test-artifacts)
* [2.5 Sample Environment](#2.5-sample-environment)
* [2.6 Hosts File for Sample Environment](#2.6-hosts-file-for-sample-environment)
* [**3 GSTP USAGE**](#3-gstp-usage)
* [3.1 Generating Test Scripts](#3.1-generating-test-scripts)
* [3.2 Executing GSTP Test Cases](#3.2-executing-gstp-test-cases)
* [3.3 Reviewing Logs](#3.3-reviewing-logs)
  * [3.3.1 Summary Results](#3.3.1-summary-results)
  * [3.3.2 Client Log](#3.3.2-client-log)
  * [3.3.3 Validation Failures Re-execution Script](#3.3.3-validation-failures-re-execution-script)
  * [3.3.4 Profile Evaluation Failures Re-execution Script](#3.3.4-profile-evaluation-failures-re-execution-script)
  * [3.3.5 Artifacts](#3.3.5-artifacts)
  * [3.3.6 Debug](#3.3.6-debug)
* [**4 DEPLOYING ARTIFACTS**](#4-deploying-artifacts)
* [4.1 Local Virtual Machines](#4.1-local-virtual-machines)
* [4.2 Amazon Web Services Image](#4.2-amazon-web-services)
* [4.3 Artifact Archives](#4.3-artifact-archives)
* [**BIBLIOGRAPHY**](#bibliography)

## 1 Overview

This document provides an overview of the artifacts and utilities employed by the U.S. General Services Administration's (GSA) Server-based Certificate Validation Protocol (SCVP) Test Program (GSTP). The GSTP's goal is to confirm whether an SCVP Responder is capable of providing accurate certification path validation results in environments with comparable complexity to the U.S. Federal Public Key Infrastructure (FPKI). The test materials do not facilitate confirmation that a product is conformant with all aspects of the SCVP, as defined in [Request for Comment (RFC) 5055].<!--Fixed 5005 to 5055, per Bibliography.--> Instead, conformance to the SCVP profiles identified for use by GSA [TREAS] is demonstrated.

The GSTP is composed of seven primary components that are used to exercise an SCVP Responder under Test (RUT):

*	Test SCVP client
*	Test SCVP client scripts 
*	Test SCVP client script generator
*	Test SCVP client script runner (optional)
*	Test artifacts, i.e., certificates and revocation information
*	Sample environment for hosting certificates and revocation information
*	Hosts file to resolve names hosted by sample environment

The test SCVP client is provided along with a set of scripts to cause the client to use the test artifacts to interact with a RUT. The test client will emit several streams of information including a summary of test results; basic logging information regarding test client operation; scripts to facilitate re-testing scenarios that failed to yield the expected results; debugging information; and, optionally, request and response files for analysis.

A script generator is supplied to generate scripts to drive the test SCVP client. The script generator emits scripts for each set of test artifacts with several variations for interacting with the RUT.

Three distinct sets of test artifacts will be used to test certification path development and certification path validation capabilities:

1. NIST’s Public Key Infrastructure (PKI) Interoperability Test Suite v2 (PKITSv2)
2. NIST’s Path Development Test Suite v2 (PDTSv2)
3. Mock-Federal PKI (MFPKI)

All Authority Information Access (AIA) and Certificate Revocation List (CRL) Distribution Point (DP) Uniform Resource Identifiers (URIs) included in the test artifacts' feature names <!--missing verb-->that are not routable on the public Internet. A Linux virtual machine that hosts artifacts via HTTP server and OCSP responder instances is available, along with a host file that can be tailored for use in resolving names during certification path processing.

* [Back to Table of Contents](#table-of-contents)

## 2 GSTP Components

### 2.1 Test SCVP Client

The GSTP test client is based on an SCVP client available from GitHub.com/GSA at: [GSA/VSS](https://github.com/GSA/vss){:target="_blank"}._ <!--This link gives 404 error due to Private Repo.-->The GSTP client will also be available via GitHub at a TBD location. The command line parameters accepted by the client are as follows:

Parameter Name|Parameter Type|Description|
---|---|---|
-h, --help|None|Show help message and exit|
&nbsp;&nbsp;---------------------|--------------**_Basic Logistics_**---------------|----------------------------------&nbsp;&nbsp;|
--scvp_profile|{lightweight, long-term-record, batch}|Name of SCVP profile|
-x, --expectSuccess|Boolean value {true, false}|Indicates whether success is expected when validating the --target_cert. Defaults to true|
-l, --logging_conf|Full path and filename of log4j configuration file|Used to customize default logging behavior|
-n, --test_case_name|String value|Friendly name of test case|
-z, --signer_certs|Path to directory to receive certificate(s) used to validate SCVP responses|Save signer certificates as read from a validation policy response to a specified directory then exit|
--log_all_messages|None|Log all requests and responses to the artifacts log, not just those from failed tests. Off by default.|
&nbsp;&nbsp;---------------------|----------**_Target Certificate Details_**---------|----------------------------------&nbsp;&nbsp;|
-c, --target_cert|Full path and filename of binary DER encoded certificate|Certificate presented to responder for validation; not used when 
--scvp_profile is set to batch, required otherwise|
-b, --batch_folder|Full path of folder containing binary DER encoded certificates|Certificates presented to responder for validation; used when --scvp_profile is set to batch, not used otherwise|
-t, --trust_anchor|Full path and filename of binary DER encoded certificate|Certificate presented to responder as trust anchor to use for validation; omitted from request by default|
&#8209;&#8209;batch_folder_success|Full path of folder containing binary DER encoded certificates|Certificates presented to responder for validation; used when --scvp_profile is set to batch, not used otherwise; all certificates are expected to validate successfully|
--batch_folder_failure|Full path of folder containing binary DER encoded certificates|Certificates presented to responder for validation; used when --scvp_profile is set to batch, not used otherwise; all certificates are expected to fail validation|
&nbsp;&nbsp;---------------------|------------**_SCVP Request Details_**-----------|----------------------------------&nbsp;&nbsp;|
-v, --validation_policy|Object identifier value expressed in dot notation form (i.e., 1.2.3.4.5)|Validation policy to include in request; default value is 1.3.6.1.5.5.7.19.1|
--wantBacks|One or more symbolic WantBack names {Cert, BestCertPath, RevocationInfo, PublicKeyInfo, AllCertPaths, EeRevocationInfo, CAsRevocationInfo}|WantBack value(s) to include in request; default is BestCertPath|
&nbsp;&nbsp;---------------------|**_Certification Path Validation </br>Algorithm Inputs_**|----------------------------------&nbsp;&nbsp;|
-p, --certificate_policy|One or more object identifiers expressed in dot notation form (i.e., 1.2.3.4.5)|Certificate policies to use as the user supplied policy set; omitted from request by default|
--inhibitAnyPolicy|Boolean value {true, false}|Boolean value to use as inhibitAnyPolicy; omitted from request by default|
&#8209;&#8209;inhibitPolicyMapping|Boolean value {true, false}|Boolean value to use as inhibitPolicyMapping; omitted from request by default|
--requireExplicitPolicy|Boolean value {true, false}|Boolean value to use as requireExplicitPolicy; omitted from request by default|


Logging output is written to a location identified by the SCVP_OUTPUT_PATH environment variable.

Generally, the client need not be interacted with directly to execute test cases. A set of scripts are provided that drive execution of test scenarios in a variety of contexts. However, prior to using the scripts, the test client itself must be configured to interact with the RUT. A configuration file must be edited to provide the URL of the SCVP interface and a key store must be updated to include keys necessary to verify the SCVP responses. The configuration file is named `vss.properties` and is located in the `/usr/local/tomcat/conf` folder. The table below shows the settings that must be modified for test purposes.

Configuration Element|Purpose|Example Value|
---|---|:---:|
VSS_TRUSTSTORE_SCVP_SIGNER_ISSUER_LABEL|Provides label of SCVP responder’s certificate in the keystore|Some Responder|
VSS_SCVP_SERVER_URI|Provides the URI to which SCVP requests are sent|http://example.com/scvp|
VSS_SCVP_DER_ENCODE_DEFAULTS|Determines whether the client DER encodes default fields (some responders require presence of fields the DER requires to be absent)|False|
VSS_SCVP_TEST_CLIENT|Governs custom test client behavior that is only appropriate in a test client|True|


Alternatively, the location of the `vss.properties` file can be provided as a Java system variable when the client is launched as shown below (which also shows temporarily reassignment of the `SCVP_OUTPUT_PATH` environment variable for a single run):

```
SCVP_OUTPUT_PATH=/<some path>/SCVP_OUTPUT_PATH2 java -Dvss.configLocation=/<some path>/vss.properties -jar vss2.jar --scvp_profile lightweight -n 4.1.1 -c /<some path>/ValidCertificatePathTest1EE.crt --wantBacks BestCertPath
```
Once the configuration file edits have been performed, the RUT’s certificate must be added to the `keystore.ks` file located in the `/usr/local/tomcat/conf` folder. If the RUT’s certificate is not handy and the RUT supports validation policy requests, the test client can be used to retrieve the certificate via the following command:

```
java –jar vss2.jar –s /path/to/receive/certificate.der 
```
The certificate may then be imported into the keystore using:

```
keytool -keystore /usr/local/tomcat/conf/vssTrustStore.jks -importcert -file /path/to/receive/certificate.der -alias someresponder 
```
The test client will write logs to the location identified by the `SCVP_OUTPUT_PATH` environment variable.

* [Back to Table of Contents](#table-of-contents)

### 2.2 Test SCVP Client Scripts and Script Generator

During the execution of the GSTP, the test SCVP client will be executed hundreds of times. To simplify execution of the test cases, a set of scripts are provided that reference a target certificate or collection of target certificates and provide a set of appropriate command line parameters. These scripts can be modified for the environment in which the test client will be used. Scripts may be manually altered or regenerated to change paths to test artifacts, to change output folder location or to change the list of wantBacks.

-----------------------|---------------------**_ScvpScriptGenerator v1.0.0 Usage_**-----------------------------------|
:---|---|
-h&nbsp;[&nbsp;--help&nbsp;]|Print usage instructions|
-l&nbsp;[&nbsp;&#8209;&#8209;logging_conf&nbsp;]&nbsp;arg|Logging configuration to support report generation|
&#8209;&#8209;pkits_2048_folder&nbsp;arg|Folder containing PKITS 2048 edition (root of Renamed folder containing 0, 1, 2, etc., folders and all certificates)|
&#8209;&#8209;pkits_4096_folder&nbsp;arg|Folder containing PKITS 4096 edition (root of Renamed folder containing 0, 1, 2, etc., folders and all certificates)|
&#8209;&#8209;pkits_p256_folder&nbsp;arg|Folder containing PKITS p256 edition (root of Renamed folder containing 0, 1, 2, etc., folders and all certificates)|
&#8209;&#8209;pkits_p384_folder&nbsp;arg|Folder containing PKITS p384 edition (root of Renamed folder containing 0, 1, 2, etc., folders and all certificates)|
--pdts_folder&nbsp;arg|Folder containing PDTS edition|
--mfpki_folder&nbsp;arg|Folder containing MFPKI edition|
--mfpki_ta&nbsp;arg|File containing the MFPKI trust anchor|
--output_folder&nbsp;arg|Folder to receive generated scripts|
-l&nbsp;[&nbsp;--logging&nbsp;]&nbsp;arg|Logging configuration for ScvpScriptGenerator logging purposes|
--want_back&nbsp;arg|List of OIDS in dot notation form (i.e., 1.2.3.4.5) to be passes as --wantBacks to the SCVP client|

The following script can be tailored to regenerate a full complement of scripts to support execution of the GSTP against a given SCVP responder:

```
./ScvpScriptGenerator --mfpki_folder /<path>/MFPKI/EEs --mfpki_ta /<path>/MFPKI/TAs/905F942FD9F28F679B378180FD4F846347F645C1.fake.der 
--output_folder /<path>/GSTP --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pdts_folder /<path>/PDTS/Renamed --output_folder /<path>/GSTP --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_2048_folder /<path>/PKITS_2048/Renamed 
--output_folder /<path>/GSTP --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_4096_folder /<path>/PKITS_4096/Renamed 
--output_folder /<path>/GSTP --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_p256_folder /<path>/PKITS_P256/Renamed 
--output_folder /<path>/GSTP --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_p384_folder /<path>/PKITS_P256/Renamed 
--output_folder /<path>/GSTP --want_back BestCertPath --want_back RevocationInfo
```
The resulting output will be a set of scripts, as listed below. For the MFPKI and each PKITSv2 edition, a script targeting the default SCVP validation policy will be emitted both with and without trust anchor inclusion in the request for each SCVP profile type. PDTS will receive similar, except no batch scripts are emitted for PDTS. Similarly, for the MFPKI and each PKITSv2 edition, a script targeting a non-default SCVP validation policy will be emitted for each profile type. PDTS will receive similar, except that no batch script is emitted. Fifty-one scripts are generated:

*	MFPKI_DEFAULT_OMIT_TA_batch.sh
*	MFPKI_DEFAULT_OMIT_TA_lightweight.sh
*	MFPKI_DEFAULT_OMIT_TA_longterm.sh
*	MFPKI_DEFAULT_WITH_TA_batch.sh
*	MFPKI_DEFAULT_WITH_TA_lightweight.sh
*	MFPKI_DEFAULT_WITH_TA_longterm.sh
*	MFPKI_NON_DEFAULT_batch.sh
*	MFPKI_NON_DEFAULT_lightweight.sh
*	MFPKI_NON_DEFAULT_longterm.sh
*	PDTS_DEFAULT_OMIT_TA_lightweight.sh
*	PDTS_DEFAULT_OMIT_TA_longterm.sh
*	PDTS_DEFAULT_WITH_TA_lightweight.sh
*	PDTS_DEFAULT_WITH_TA_longterm.sh
*	PDTS_NON_DEFAULT_lightweight.sh
*	PDTS_NON_DEFAULT_longterm.sh
*	PKITS_2048_DEFAULT_OMIT_TA_batch.sh
*	PKITS_2048_DEFAULT_OMIT_TA_lightweight.sh
*	PKITS_2048_DEFAULT_OMIT_TA_longterm.sh
*	PKITS_2048_DEFAULT_WITH_TA_batch.sh
*	PKITS_2048_DEFAULT_WITH_TA_lightweight.sh
*	PKITS_2048_DEFAULT_WITH_TA_longterm.sh
*	PKITS_2048_NON_DEFAULT_batch.sh
*	PKITS_2048_NON_DEFAULT_lightweight.sh
*	PKITS_2048_NON_DEFAULT_longterm.sh
*	PKITS_4096_DEFAULT_OMIT_TA_batch.sh
*	PKITS_4096_DEFAULT_OMIT_TA_lightweight.sh
*	PKITS_4096_DEFAULT_OMIT_TA_longterm.sh
*	PKITS_4096_DEFAULT_WITH_TA_batch.sh
*	PKITS_4096_DEFAULT_WITH_TA_lightweight.sh
*	PKITS_4096_DEFAULT_WITH_TA_longterm.sh
*	PKITS_4096_NON_DEFAULT_batch.sh
*	PKITS_4096_NON_DEFAULT_lightweight.sh
*	PKITS_4096_NON_DEFAULT_longterm.sh
*	PKITS_P256_DEFAULT_OMIT_TA_batch.sh
*	PKITS_P256_DEFAULT_OMIT_TA_lightweight.sh
*	PKITS_P256_DEFAULT_OMIT_TA_longterm.sh
*	PKITS_P256_DEFAULT_WITH_TA_batch.sh
*	PKITS_P256_DEFAULT_WITH_TA_lightweight.sh
*	PKITS_P256_DEFAULT_WITH_TA_longterm.sh
*	PKITS_P256_NON_DEFAULT_batch.sh
*	PKITS_P256_NON_DEFAULT_lightweight.sh
*	PKITS_P256_NON_DEFAULT_longterm.sh
*	PKITS_P384_DEFAULT_OMIT_TA_batch.sh
*	PKITS_P384_DEFAULT_OMIT_TA_lightweight.sh
*	PKITS_P384_DEFAULT_OMIT_TA_longterm.sh
*	PKITS_P384_DEFAULT_WITH_TA_batch.sh
*	PKITS_P384_DEFAULT_WITH_TA_lightweight.sh
*	PKITS_P384_DEFAULT_WITH_TA_longterm.sh
*	PKITS_P384_NON_DEFAULT_batch.sh
*	PKITS_P384_NON_DEFAULT_lightweight.sh
*	PKITS_P384_NON_DEFAULT_longterm.sh

* [Back to Table of Contents](#table-of-contents)

### 2.3	Test SCVP Client Script Runner

The following script can be used to execute all GSTP test cases when run from a folder containing the test SCVP client with all logs collecting in one location:

```
bash /<path>/MFPKI_DEFAULT_OMIT_TA_batch.sh
bash /<path>/MFPKI_DEFAULT_OMIT_TA_lightweight.sh
bash /<path>/MFPKI_DEFAULT_OMIT_TA_longterm.sh
bash /<path>/MFPKI_DEFAULT_WITH_TA_batch.sh
bash /<path>/MFPKI_DEFAULT_WITH_TA_lightweight.sh
bash /<path>/MFPKI_DEFAULT_WITH_TA_longterm.sh
bash /<path>/MFPKI_NON_DEFAULT_batch.sh
bash /<path>/MFPKI_NON_DEFAULT_lightweight.sh
bash /<path>/MFPKI_NON_DEFAULT_longterm.sh
bash /<path>/PDTS_DEFAULT_OMIT_TA_lightweight.sh
bash /<path>/PDTS_DEFAULT_OMIT_TA_longterm.sh
bash /<path>/PDTS_DEFAULT_WITH_TA_lightweight.sh
bash /<path>/PDTS_DEFAULT_WITH_TA_longterm.sh
bash /<path>/PDTS_NON_DEFAULT_lightweight.sh
bash /<path>/PDTS_NON_DEFAULT_longterm.sh
bash /<path>/PKITS_2048_DEFAULT_OMIT_TA_batch.sh
bash /<path>/PKITS_2048_DEFAULT_OMIT_TA_lightweight.sh
bash /<path>/PKITS_2048_DEFAULT_OMIT_TA_longterm.sh
bash /<path>/PKITS_2048_DEFAULT_WITH_TA_batch.sh
bash /<path>/PKITS_2048_DEFAULT_WITH_TA_lightweight.sh
bash /<path>/PKITS_2048_DEFAULT_WITH_TA_longterm.sh
bash /<path>/PKITS_2048_NON_DEFAULT_batch.sh
bash /<path>/PKITS_2048_NON_DEFAULT_lightweight.sh
bash /<path>/PKITS_2048_NON_DEFAULT_longterm.sh
bash /<path>/PKITS_4096_DEFAULT_OMIT_TA_batch.sh
bash /<path>/PKITS_4096_DEFAULT_OMIT_TA_lightweight.sh
bash /<path>/PKITS_4096_DEFAULT_OMIT_TA_longterm.sh
bash /<path>/PKITS_4096_DEFAULT_WITH_TA_batch.sh
bash /<path>/PKITS_4096_DEFAULT_WITH_TA_lightweight.sh
bash /<path>/PKITS_4096_DEFAULT_WITH_TA_longterm.sh
bash /<path>/PKITS_4096_NON_DEFAULT_batch.sh
bash /<path>/PKITS_4096_NON_DEFAULT_lightweight.sh
bash /<path>/PKITS_4096_NON_DEFAULT_longterm.sh
bash /<path>/PKITS_P256_DEFAULT_OMIT_TA_batch.sh
bash /<path>/PKITS_P256_DEFAULT_OMIT_TA_lightweight.sh
bash /<path>/PKITS_P256_DEFAULT_OMIT_TA_longterm.sh
bash /<path>/PKITS_P256_DEFAULT_WITH_TA_batch.sh
bash /<path>/PKITS_P256_DEFAULT_WITH_TA_lightweight.sh
bash /<path>/PKITS_P256_DEFAULT_WITH_TA_longterm.sh
bash /<path>/PKITS_P256_NON_DEFAULT_batch.sh
bash /<path>/PKITS_P256_NON_DEFAULT_lightweight.sh
bash /<path>/PKITS_P256_NON_DEFAULT_longterm.sh
bash /<path>/PKITS_P384_DEFAULT_OMIT_TA_batch.sh
bash /<path>/PKITS_P384_DEFAULT_OMIT_TA_lightweight.sh
bash /<path>/PKITS_P384_DEFAULT_OMIT_TA_longterm.sh
bash /<path>/PKITS_P384_DEFAULT_WITH_TA_batch.sh
bash /<path>/PKITS_P384_DEFAULT_WITH_TA_lightweight.sh
bash /<path>/PKITS_P384_DEFAULT_WITH_TA_longterm.sh
bash /<path>/PKITS_P384_NON_DEFAULT_batch.sh
bash /<path>/PKITS_P384_NON_DEFAULT_lightweight.sh
bash /<path>/PKITS_P384_NON_DEFAULT_longterm.sh
```

The following Python code (provided as `GSTPScriptRunner.py`) can be used to run the scripts listed above with logs moved in between each script:

```
import glob2
from optparse import OptionParser
import os
from os.path import join
import signal
from subprocess import PIPE, Popen
import sys
from time import gmtime, strftime

BASH_EXE = "/bin/bash"

bash_process = None


# noinspection PyUnusedLocal
def signal_handler(signal_param, frame_param):
    if bash_process:
        bash_process.kill()
        print('Killed GSTP test execution process')
    sys.exit(0)


def main():
    parser = OptionParser()
    parser.add_option("-i", "--inputFolder", dest="input_folder", default="",
                      help="Folder containing scripts to run")
    parser.add_option("-l", "--logFolder", dest="log_folder", default="",
                      help="Folder containing logs to move")
    parser.add_option("-d", "--destLogFolder", dest="dest_log_folder", default="",
                      help="Folder containing logs to move")
    parser.add_option("-p", "--product", dest="product", default="",
                      help="Short name of product under test (for use in naming relocated log folders)")

    (options, args) = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    global bash_process

    log_folder = options.log_folder
    orig_dest_log_folder = options.dest_log_folder
    product = options.product

    if os.path.isfile(os.path.join(log_folder, 'artifacts.csv')):
        os.remove(os.path.join(log_folder, 'artifacts.csv'))
    if os.path.isfile(os.path.join(log_folder, 'results.csv')):
        os.remove(os.path.join(log_folder, 'results.csv'))
    if os.path.isfile(os.path.join(log_folder, 'client.txt')):
        os.remove(os.path.join(log_folder, 'client.txt'))
    if os.path.isfile(os.path.join(log_folder, 'validation_failures.txt')):
        os.remove(os.path.join(log_folder, 'validation_failures.txt'))
    if os.path.isfile(os.path.join(log_folder, 'profile_failures.txt')):
        os.remove(os.path.join(log_folder, 'profile_failures.txt'))

    if options.input_folder:
        only_files = glob2.glob(options.input_folder + '/*.sh')

        for filename in only_files:
            t = strftime("%Y%m%d%H%M%S", gmtime())
            print("Started " + filename + " at " + t)

            bash_command = BASH_EXE + " " + join(options.input_folder, filename)
            bash_process = Popen(bash_command, shell=True, stdout=PIPE)
            bash_process.wait()


            # noinspection PyUnusedLocal
            process = None

            dest_log_folder = os.path.join(orig_dest_log_folder, product + "_" +
                                           os.path.splitext(os.path.basename(filename))[0] + "_" + t)
            os.mkdir(dest_log_folder)
            if os.path.isfile(os.path.join(log_folder, 'artifacts.csv')):
                os.rename(os.path.join(log_folder, 'artifacts.csv'), os.path.join(dest_log_folder, 'artifacts.csv'))
            if os.path.isfile(os.path.join(log_folder, 'results.csv')):
                os.rename(os.path.join(log_folder, 'results.csv'), os.path.join(dest_log_folder, 'results.csv'))

            art_files = glob2.glob(options.log_folder + '/artifacts*.csv')
            for art in art_files:
                if os.path.isfile(art):
                    os.rename(art, os.path.join(dest_log_folder, os.path.basename(art)))

            res_files = glob2.glob(options.log_folder + '/results*.csv')
            for res in res_files:
                if os.path.isfile(res):
                    os.rename(res, os.path.join(dest_log_folder, os.path.basename(res)))

            if os.path.isfile(os.path.join(log_folder, 'client.txt')):
                os.rename(os.path.join(log_folder, 'client.txt'), os.path.join(dest_log_folder, 'client.txt'))
            if os.path.isfile(os.path.join(log_folder, 'debug.txt')):
                os.rename(os.path.join(log_folder, 'debug.txt'), os.path.join(dest_log_folder, 'debug.txt'))
            if os.path.isfile(os.path.join(log_folder, 'validation_failures.txt')):
                os.rename(os.path.join(log_folder, 'validation_failures.txt'), os.path.join(dest_log_folder,
                                                                                            'validation_failures.txt'))
            if os.path.isfile(os.path.join(log_folder, 'profile_failures.txt')):
                os.rename(os.path.join(log_folder, 'profile_failures.txt'), os.path.join(dest_log_folder,
                                                                                         'profile_failures.txt'))

            t2 = strftime("%Y%m%d%H%M%S", gmtime())
            print("Completed " + filename + " at " + t2)


if __name__ == '__main__':
    main()
```

This script will run all available scripts in the designated folder. To refrain from running certain scripts, simply delete or move them. For example, if not testing non-default validation policies, remove all of the scripts with _non-default_ in the name.

* [Back to Table of Contents](#table-of-contents)

### 2.4	Test Artifacts

PKITSv2 and PDTSv2 are updates to the existing NIST test suites. PKITS was updated to add AIA and CRL DP extensions to avoid the need to make all artifacts available locally to the product being tested. Additionally, editions were prepared using alternative public key and hash algorithms. PDTS was updated to feature unexpired artifacts, to drop Lightweight Directory Access Protocol (LDAP)-centric tests and to use RSA 2048 keys with SHA256 (instead of RSA 1024 with SHA1). While these were generated to support the GSTP, the artifacts are suitable for testing any [RFC 5280]-compliant certification path validation implementation.

Test Suite|Public Key Details|Hash Algorithm|
:---:|:---:|:---:|
PKITSv2|RSA 2048|SHA256|
PKITSv2|RSA 4096|SHA512|
PKITSv2|EC p256|SHA256|
PKITSv2|EC p384|SHA384|
PDTSv2|RSA 2048|SHA256|
MFPKI|As observed (mostly RSA 2048)|As observed (mostly SHA256)|

MFPKI artifacts are cloned from the FPKI and do not have uniformly long validity periods like PDTSv2 and PKITSv2. Some artifacts that are classified as “good” will expire over time. PITTv2 can be used to periodically spot-check so expired artifacts can be removed from service and/or re-refreshed using PKI Copy and Paste (PCP).

* [Back to Table of Contents](#table-of-contents)

### 2.5	Sample Environment

A Linux virtual machine is available that features artifacts from the MFPKI, various PKITSv2 editions hosted using Apache httpd, and OpenSSL’s OCSP responder capabilities. The environment is intended to facilitate dynamic path discovery and avoid the need to manually provide artifacts to the RUT as a prerequisite for testing certification path validation capabilities.

* [Back to Table of Contents](#table-of-contents)

### 2.6	Hosts File for Sample Environment

A sample hosts file for the URIs included in artifacts that comprise the MFPKI, various PKITSv2 editions, and PDTS is below: 

```
# ********** Hosts added by PCP VM preparation scripts **********
192.168.1.101	betty.pkits.test
192.168.1.101	invalidcertificates.gov
192.168.1.101	testserver.testcertificates.gov
192.168.1.101	testserver.invalidcertificates.gov
192.168.1.101	testcertificates.gov
# ********** End of hosts added by PCP VM preparation scripts **********
# ********** Hosts added by PCP VM preparation scripts **********
192.168.1.101	betty-4096.pkits.test
# ********** End of hosts added by PCP VM preparation scripts **********
# ********** Hosts added by PCP VM preparation scripts **********
192.168.1.101	betty-256.pkits.test
# ********** End of hosts added by PCP VM preparation scripts **********
# ********** Hosts added by PCP VM preparation scripts **********
192.168.1.101	betty-384.pkits.test
# ********** End of hosts added by PCP VM preparation scripts **********
# ********** Hosts added by PCP VM preparation scripts **********
192.168.1.101	certipath-crl-ldap.verisign.com.test
192.168.1.101	certipath-aia.verisign.com.test
192.168.1.101	www.fis.evincible.com.test
192.168.1.101	dir1.com-strong-id.net.test
192.168.1.101	ssp-crl.symauth.com.test
192.168.1.101	crlserver.orc.com.test
192.168.1.101	pki.treasury.gov.test
192.168.1.101	strong-auth.eop.gov.test
192.168.1.101	ocs1.com-strong-id.net.test
192.168.1.101	certipath-sia.symauth.com.test
192.168.1.101	pilot-tscp-aia.symauth.com.test
192.168.1.101	rootweb.managed.entrust.com.test
192.168.1.101	nfi3.eva.orc.com.test
192.168.1.101	aces.ocsp.identrust.com.test
192.168.1.101	aia1.ssp-strong-id.net.test
192.168.1.101	sia1.ssp-strong-id.net.test
192.168.1.101	ocsp.dimc.dhs.gov.test
192.168.1.101	ocsp.dhhs.gov.test
192.168.1.101	crl.pki.va.gov.test
192.168.1.101	ocsp.managed.entrust.com.test
192.168.1.101	ssp-sia.verisign.com.test
192.168.1.101	ocspaces.trustdst.com.test
192.168.1.101	certipath-crl.symauth.com.test
192.168.1.101	keys.eop.gov.test
192.168.1.101	sspdir.managed.entrust.com.test
192.168.1.101	ocsp.pki.va.gov.test
192.168.1.101	crl.gds.disa.mil.test
192.168.1.101	crl.gds.nit.disa.mil.test
192.168.1.101	crl-server.orc.com.test
192.168.1.101	crl3.digicert.com.test
192.168.1.101	pilot-tscp-sia.symauth.com.test
192.168.1.101	tstocs3.com-strong-id.net.test
192.168.1.101	ssp-aia-ldap.verisign.com.test
192.168.1.101	sbca2.safe-biopharma.org.test
192.168.1.101	ocsp.uspto.gov.test
192.168.1.101	ocsp1.ssp-strong-id.net.test
192.168.1.101	tstcdp3.com-strong-id.net.test
192.168.1.101	ocspaces.identrust.com.test
192.168.1.101	cdp1.com-strong-id.net.test
192.168.1.101	devpki.treas.gov.test
192.168.1.101	pki.strac.org.test
192.168.1.101	devldap.treas.gov.test
192.168.1.101	rootdir.managed.entrust.com.test
192.168.1.101	devx500.arc.nasa.gov.test
192.168.1.101	ldap01.dimc.dhs.gov.test
192.168.1.101	sia1.com-strong-id.net.test
192.168.1.101	gpo-crl.ois.gpo.gov.test
192.168.1.101	doesspocsp.managed.entrust.com.test
192.168.1.101	devpki.treasury.gov.test
192.168.1.101	pki.fti.org.test
192.168.1.101	pub.carillonfedserv.com.test
192.168.1.101	apps.identrust.com.test
192.168.1.101	crls.pki.state.gov.test
192.168.1.101	ldap-pte.identrust.com.test
192.168.1.101	ldap.treas.gov.test
192.168.1.101	pilot-tscp-crl.symauth.com.test
192.168.1.101	lc.nasa.gov.test
192.168.1.101	hhspkicrl.managed.entrust.com.test
192.168.1.101	ocsp.defence.gov.au.test
192.168.1.101	aia3.com-strong-id.net.test
192.168.1.101	ldap.pki.va.gov.test
192.168.1.101	sspldap.treas.gov.test
192.168.1.101	crl.boeing.com.test
192.168.1.101	certipath-aia.symauth.com.test
192.168.1.101	pki.tscplab.org.test
192.168.1.101	sspweb.managed.entrust.com.test
192.168.1.101	ldap.digicert.com.test
192.168.1.101	certrep.pki.state.gov.test
192.168.1.101	crl.identrust.com.test
192.168.1.101	orc-ds.orc.com.test
192.168.1.101	ndac.arc.nasa.gov.test
192.168.1.101	crl.global.lmco.com.test
192.168.1.101	nfi2.eva.orc.com.test
192.168.1.101	certstatus.strac.org.test
192.168.1.101	dir.boeing.com.test
192.168.1.101	dir1.ssp-strong-id.net.test
192.168.1.101	sureid-aia.symauth.com.test
192.168.1.101	servers.cmcf.state.il.us.test
192.168.1.101	pki-crl.symauth.com.test
192.168.1.101	crl-pte.identrust.com.test
192.168.1.101	s.symcb.com.test
192.168.1.101	ssp-crl-ldap.verisign.com.test
192.168.1.101	www.fis.evincibletest.com.test
192.168.1.101	igc.ocsp.identrust.com.test
192.168.1.101	crl.disa.mil.test
192.168.1.101	s.symcd.com.test
192.168.1.101	www.gpo-fbca-crls.ois.gpo.gov.test
192.168.1.101	certstatus.fti.org.test
192.168.1.101	cdp1.ssp-strong-id.net.test
192.168.1.101	ldap.icam.pgs-lab.com.test
192.168.1.101	demodoesspweb.managed.entrust.com.test
192.168.1.101	ocsp.external.lmco.com.test
192.168.1.101	www.illinois.gov.test
192.168.1.101	ldap.fpki.gov.test
192.168.1.101	dsspweb.managed.entrust.com.test
192.168.1.101	ssp-sia.symauth.com.test
192.168.1.101	crl.external.lmco.com.test
192.168.1.101	sbca2-test.safe-biopharma.org.test
192.168.1.101	www.usps.com.test
192.168.1.101	www.dcs.exostar.com.test
192.168.1.101	ssp3.eva.orc.com.test
192.168.1.101	ssp-sia-ldap.verisign.com.test
192.168.1.101	www.tscp.eads.com.test
192.168.1.101	ts-mobile-qca.aia.com-strong-id.net.test
192.168.1.101	ssp-crl.verisign.com.test
192.168.1.101	ocsp.pki.state.gov.test
192.168.1.101	ipki.uspto.gov.test
192.168.1.101	ocsp.nsn0.rcvs.nit.disa.mil.test
192.168.1.101	www.defence.gov.au.test
192.168.1.101	tscp-crl.symauth.com.test
192.168.1.101	ts-mobile-qca.ocsp.com-strong-id.net.test
192.168.1.101	pki.treas.gov.test
192.168.1.101	publicsector.ocsp.identrust.com.test
192.168.1.101	cacerts.digicert.com.test
192.168.1.101	ssp-ocsp.verisign.com.test
192.168.1.101	directory.ois.gpo.gov.test
192.168.1.101	pki.dimc.dhs.gov.test
192.168.1.101	tstaia3.com-strong-id.net.test
192.168.1.101	http.fpki.gov.test
192.168.1.101	pki.raytheon.com.test
192.168.1.101	tscp-aia.symauth.com.test
192.168.1.101	apps-stg.identrust.com.test
192.168.1.101	cdp3.com-strong-id.net.test
192.168.1.101	crl4.digicert.com.test
192.168.1.101	cacerts.test.digicert.com.test
192.168.1.101	ts-mobile-qca.crl.com-strong-id.net.test
192.168.1.101	hhspkiocsp.managed.entrust.com.test
192.168.1.101	nfimediumsspdir.managed.entrust.com.test
192.168.1.101	ssp-aia.symauth.com.test
192.168.1.101	ssp-aia.verisign.com.test
192.168.1.101	sureid-crl.symauth.com.test
192.168.1.101	dir.defence.gov.au.test
192.168.1.101	nfirootdir.managed.entrust.com.test
192.168.1.101	ocsp1.com-strong-id.net.test
192.168.1.101	public.ocsp.identrust.com.test
192.168.1.101	doesspweb.managed.entrust.com.test
192.168.1.101	ldap.identrust.com.test
192.168.1.101	http.cite.fpki-lab.gov.test
192.168.1.101	certipath-aia-ldap.verisign.com.test
192.168.1.101	dsspdir.managed.entrust.com.test
192.168.1.101	crl.nit.disa.mil.test
192.168.1.101	certdata.northropgrumman.com.test
192.168.1.101	validation.identrust.com.test
192.168.1.101	nfimediumsspweb.managed.entrust.com.test
192.168.1.101	ocsp.disa.mil.test
192.168.1.101	certipath-crl.verisign.com.test
192.168.1.101	nfiocsp.managed.entrust.com.test
192.168.1.101	dsspocsp.managed.entrust.com.test
192.168.1.101	nfirootweb.managed.entrust.com.test
192.168.1.101	ocsp.treas.gov.test
192.168.1.101	apps-pte.identrust.com.test
192.168.1.101	hc.nasa.gov.test
192.168.1.101	pilot-certipath-aia.verisign.com.test
192.168.1.101	ocsp.digicert.com.test
192.168.1.101	www.ocsp.gpo.gov.test
192.168.1.101	ssp-ocsp.symauth.com.test
192.168.1.101	dir.tscp.eads.com.test
192.168.1.101	aia1.com-strong-id.net.test
192.168.1.101	tscp-sia.symauth.com.test
192.168.1.101	http.icam.pgs-lab.com.test
192.168.1.101	onsitecrl.verisign.com.test
192.168.1.101	eid-aia.symauth.com.test
192.168.1.101	pki-ocsp.symauth.com.test
192.168.1.101	ocsp.northropgrumman.com.test
192.168.1.101	pub.carillon.ca.test
192.168.1.101	igcrootpte.ocsp.identrust.com.test
192.168.1.101	ssp4.eva.orc.com.test
# ********** End of hosts added by PCP VM preparation scripts **********
# ********** Hosts added by PCP VM preparation scripts **********
192.168.1.101	betty.nist.gov.test
192.168.1.101	smime2.nist.gov.test
# ********** End of hosts added by PCP VM preparation scripts **********
```
* [Back to Table of Contents](#table-of-contents)

## 3 GSTP Usage

### 3.1	Generating Test Scripts

Use the script generator to generate test scripts targeting the desired artifact collection. The example below demonstrates the generation of test scripts targeting all six artifact collections located in `/home/user/gstp` with scripts written to `/home/user/test`. In this example, two _wantBacks_ will be requested in each SCVP request (except batch, for which the script generator automatically omits all _wantBacks_).

```
./ScvpScriptGenerator --mfpki_folder /home/user/gstp/MFPKI/EE_good --mfpki_ta/home/user/gstp/MFPKI/TAs/Common Policy-905F942FD9F28F679B378180FD4F846347F645C1.fake --output_folder /home/user/test --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pdts_folder /home/user/gstp/PDTS/renamed --output_folder /home/user/test --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_2048_folder /home/user/gstp/PKITS_2048/renamed/ --output_folder /home/user/test --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_4096_folder /home/user/gstp/PKITS_4096/renamed --output_folder /home/user/test --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_p256_folder /home/user/gstp/PKITS_p256/renamed --output_folder /home/user/test --want_back BestCertPath --want_back RevocationInfo
./ScvpScriptGenerator --pkits_p384_folder /home/user/gstp/PKITS_p384/renamed --output_folder /home/user/test --want_back BestCertPath --want_back RevocationInfo
```
Delete any test scripts that are not of interest. For example, if not testing non-default validation policies, delete those scripts. 

* [Back to Table of Contents](#table-of-contents)

### 3.2	Executing GSTP Test Cases

The RUT must be configured with all necessary trust anchors, any non-default validation policies, and the hosts file targeting the hosting environment that will be used. The test client must be configured to interact with the responder (in the `vss.properties` file) and save logs to an appropriate location (via the `SCVP_OUTPUT_PATH` environment variable). 

After the RUT and client are configured, simply execute the desired test scripts and review the results. Make sure to delete any output files prior to test execution, if desired, because output files will be appended to throughout execution. The test runner script can be used to handle log file management.

* [Back to Table of Contents](#table-of-contents)

### 3.3	Reviewing Logs

The test SCVP client is configured to emit six log streams, as described in the following subsections.

#### 3.3.1 Summary Results

The summary results file is written to `results.csv` and contains a brief summary of test SCVP client execution. It includes friendly name for a test, the expected result, an indication of expected result achieved, and an indication of profile conformance evaluation.

#### 3.3.2 Client Log

The client log is written to `client.txt`. It contains additional detail not presented in the summary results. For example, an indication of which fields in an SCVP response caused profile-conformance evaluation failure.

#### 3.3.3 Validation Failures Re-execution Script

The validation failures re-execution script is written to `validation_failures.txt`. It includes invocations of the test SCVP client to enable re-execution of test cases that failed to yield the expected result with regard to validation of the target certificate(s).

#### 3.3.4 Profile Evaluation Failures Re-execution Script

The profile failures re-execution script is written to `profile_failures.txt`. It includes invocations of the test SCVP client to enable re-execution of test cases that failed to yield the expected result with regard to evaluation of the SCVP response against the target SCVP profile.

#### 3.3.5 Artifacts

Base64-encoded SCVP requests and responses corresponding to failed test cases are written to `artifacts.csv` to facilitate detailed analysis using a utility like `dumpasn1`. To capture all request and responses, pass the `--log_all_messages` flag to the client.

#### 3.3.6 Debug

A debug log that includes all of the above, plus lower level library output, is emitted to aid in troubleshooting. The log information emitted by lower level libraries may include details that are not propagated back to the test client.

* [Back to Table of Contents](#table-of-contents)

## 4 Deploying Artifacts

The test PKI artifacts are supplied in three forms:

* Compressed archives containing only the artifacts themselves
* Installed on Virtual Machines (VMs) intended to be deployed locally
* Installed on an Amazon Web Services (AWS) image, suitable for deployment as an Elastic Compute Cloud (EC2) instance.

### 4.1	Local Virtual Machines

Two VMs intended for local use are supplied. One includes the PCP tool used to generate the artifacts along with assorted other tools suitable for inspecting and testing them. It also includes a copy of the test harness and related utilities, ready to run to test an SCVP service.

The second VM includes a copy of all the artifacts and software configured to host them at the locations referenced in the certificates and service OCSP responses.

* [Back to Table of Contents](#table-of-contents)

#### 4.1.1 Tools VM

The SCVP Tools VM is supplied in Open Virtualization Format (OVF). In addition to being used to generate artifacts, it can be used to administer the artifacts VM.

* User:&nbsp;&nbsp;_pcpadmin_
* Password:&nbsp;&nbsp;_aqswdefr1234!_

The Tools VM should be deployed to the same virtual network as the artifact hosting VM. The _pcpadmin_ user has an SSH keypair installed which can be used to administer the artifact hosting VM.

The Tools included:

* All scripts and clients referenced in this guide, including copies of the sample hosts files that match the artifacts hosted in the Host VM, EC2 and Linode
* PCP itself
* FileZilla, for managing files on the hosting VM
* Firefox web browser
* Publication scripts referenced in the artifact publication guide
* Graphical Trust Anchor Constraints Tool (TACT) tools for editing settings databases and Trust Anchor stores
* openssl
* dumpasn1
* Xca
* Python 2 and Python 3
* PyCharm Community Edition

* [Back to Table of Contents](#table-of-contents)

#### 4.1.2 Artifact-Hosting VM

The artifact-hosting VM supplied in OVF. It is intended to be run without a graphical interface of any kind. It needs to have one interface on the same network as the Tools VM and one interface on the same network as the RUT. The hosts file installed on the RUT must reference the IP address of this network interface.

Once the artifact-hosting VM is connected, log into the console using the following credentials:

* User:&nbsp;&nbsp;_vmadmin_
* Password:&nbsp;&nbsp;_aqswdefr1234!_

Use the `ip` command to find the current address of the network adapter connected to the RUT network:

```
[vmadmin@ficam-artifacts ~]$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:be:31:f5 brd ff:ff:ff:ff:ff:ff
    inet 192.168.99.210/24 brd 192.168.99.255 scope global dynamic ens33
       valid_lft 1547sec preferred_lft 1547sec
    inet6 fe80::f090:3a80:a0f2:b37c/64 scope link
       valid_lft forever preferred_lft forever
3: ens34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:be:31:ff brd ff:ff:ff:ff:ff:ff
    inet 10.142.42.2/24 brd 10.142.42.255 scope global ens34
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:febe:31ff/64 scope link
       valid_lft forever preferred_lft forever
```
Also, update the addresses in the hosts file installed on the RUT accordingly.

Start the `httpd` service by running the command:  

```
# systemctl start httpd
```

If the RUT will be using OCSP as well as CRLs to check status, open a command prompt in `/srv/ocsp` and run the command: 

```
# bash startall.sh 
```
* [Back to Table of Contents](#table-of-contents)

### 4.2	Amazon Web Services Image

The AWS image is functionally identical to the local VM. Responders installed in the same AWS cloud can use its private IP address to access artifacts. Responders installed elsewhere can be added to the scvp-artifact-hosting security group and use the public IP of the ficam-scvp-artifacts VM.

### 4.3	Artifact Archives

Artifacts are also supplied in zip archives within the Tools VM, as well as published in the ficam-scvp-testing GitHub repository. These can be loaded into the SCVP responders per the vendor documentation for doing so.

* [Back to Table of Contents](#table-of-contents)

## Bibliography

* [RFC 5055] Freeman, T., Housley, R., Malpani, A., Cooper, D., and W. Polk, "Server-Based Certificate Validation Protocol (SCVP)," December 2007.
* [RFC 5280] Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., and Polk, W., "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile," May 2008. 
* [TREAS] Treasury Validation Services: SCVP Request and Response Profile, October 7, 2016.
