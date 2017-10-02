---
layout: default
title: Generating SCVP Test Program Artifacts
permalink: /scvpartifactsguide/
---

### Revision History 

Date|Version|Changes|
:---:|:---:|---|
08/08/2017|1.0|Final Publication|

### Table of Contents

**ADD TOC IN + a bunch of Appendices**

## 1 Overview

This document describes the test artifacts that will be generated and used as part of the U.S. General Services Administration's (GSA) Server-based Certificate Validation Protocol (SCVP) Test Program (GSTP) testing initiative. The GSTP's goal is to confirm whether an SCVP Responder is capable of providing accurate certification path validation results in environments with comparable complexity to the U.S. Federal Public Key Infrastructure (FPKI). <!--Added goal statement here from user's guide to give more complete information.-->

Three distinct sets of test artifacts will be used to test certification path development and certification path validation capabilities: <!--Added purpose statement from user's guide to give more complete information.-->

1. NIST’s Public Key Infrastructure (PKI) Interoperability Test Suite v2 (PKITSv2)
2. NIST’s Path Development Test Suite v2 (PDTSv2)
3. Mock-Federal PKI (MFPKI)

The remainder of this document describes the **nature** of each artifact set and the procedures needed to generate them. The artifacts described herein are generated using the PKI Copy and Paste (PCP) utility. For PKITS, PCP is used to generate the test artifacts containing algorithms and key sizes other than RSA-2048. For PDTS, PCP is used to refresh an expired test suite and to modify the URLs used for hosting. For MFPKI, PCP is used to generate artifacts of comparable complexity as the production FPKI. The following table describes the target end results:

Test Suite|Public Key Details|Hash Algorithm|Hosting Strategy|
---|:---:|:---:|:---|
PKITS|RSA 2048|SHA256|Not hosted; zip file|
PKITS|RSA 4096|SHA256|Not hosted; zip file|
PKITS|EC p256|SHA256|Not hosted; zip file|
PKITS|EC p384|SHA384|Not hosted; zip file|
PDTS|RSA 2048|SHA256|Downloadable VM|
PDTS|RSA 2048|SHA256|CITE-hosted|

> **Note:**&nbsp;&nbsp;The PKITS and PDTS varieties are not intended to be used simultaneously. Artifacts from one data set bear a strong resemblance to the corresponding artifacts in another data set. Each variety should be tested in isolation from the others.

## 2 Test Artifacts

### 2.1	PKITS

#### 2.1.1 Inputs

The PKITS_data.zip file from [NIST Public Key Infrastructure Testing](https://csrc.nist.gov/projects/pki-testing){:target="_blank"}_ will provide certificates and CRLs that will be input into PCP to facilitate cloning. (At the NIST website, see the **Path Validation Testing Program** section and click on the _test data_ link.) Because Digital Signature Algorithm (DSA) will not be used in the SCVP testing program, the following artifacts will not be cloned and can be omitted from the input data:

*	DSACACert.crt
*	DSAParametersInheritedCACert.crt
*	InvalidDSASignatureTest6EE.crt
*	ValidDSAParameterInheritanceTest5EE.crt
*	ValidDSASignaturesTest4EE.crt
*	DSACACRL.crl
*	DSAParametersInheritedCACRL.crl

Additionally, since neither Lightweight Directory Access Protocol (LDAP) nor S/MIME is a target for the SCVP testing program, the `certpairs` and `smime` folders can be ignored entirely.

Two certificate objects must be resigned prior to cloning. These artifacts are: `InvalidEESignatureTest3EE.crt` and `BadSignedCACert.crt`. `GoodCACert.p12` and `TrustAnchorRootCertificate.p12` sign these artifacts, respectively. (See _Appendix B_ for steps to extract PKCS #8 keys from the PKCS #12 files and resign the two certificate files. This step needs to be performed just once, with the altered data set used as input to each cloning operation.) 

#### 2.1.2 Generation Procedures

##### 2.1.2.1	Preparing PKITS for Cloning

> **Note:**nbsp;nbsp;Steps 1-3 apply when using NIST’s PKITS edition. (See _Appendix F_ for details on PKITSv2 data set [i.e., PKITS with Authority Information Access (AIA) and Certificate Revocation List (CRL) Distribution (DP) extensions].)

To prepare a PKITS data set for cloning, perform the following steps:

1. Download the `PKITS_data.zip`. 
2. Extract the zip file.
3. Resign the necessary artifacts (`InvalidEESignatureTest3EE.crt` and `BadSignedCACert.crt`) using the steps given in _Appendix B_.
4. Use the `PkitsPdtsReduction` utility to omit DSA artifacts:&nbsp;&nbsp;`python PkitsPdtsReduction.py -v` (path to extracted zip).
5. **CB STOPPED EDIT HERE** Clean the CRLs folders used by PCP to store “real” CRLs and “fake” CRLs. The location is specified in Options->Preferences->CRLs folder. Delete the contents of the real and fake directories beneath the location identified in the CRL folder setting.
6. Optionally, delete log file (location specified in the dialog accessed via Options->Preferences->LoggingConfiguration->Create/edit/view configuration).
7. Create a new PCP database (File->New PCP Database).
8. Import PKITS certificates by navigating to the Certificates tab and clicking the Import Certificates button and browsing to the certs folder within the reduced PKITS_data folder. 400 certificates should be imported.
9. Find the Invalid Missing basicConstraints EE Certificate Test 1 certificate (certificate hash value `F5042289168F331674FCEE68D4170A0A640588D6`) and delete it. Click Import Certificate and browse to the `InvalidMissingbasicConstraintsTest1EE.crt` to re-import it. This is necessary to establish the relationship to a certificate that was not imported as a CA.
10.	Import PKITS CRLs by navigating to the CRLs tab and clicking the Import CRLs button and browsing to the crls folder within the reduced PKITS_data folder. This will simply copy the files to the real folder beneath the configured CRL folder. A total of 171 CRLs should be imported.
11. Save the PCP database.
12. Close the PCP database.

##### 2.1.2.2	Basic PKITS clone generation

To prepare a cloned PKITS data set, perform the following steps:

1. Open the PCP database prepared per section 2.1.2.1 and altered via any customizations in 2.1.2.3-2.1.2.6.
2. Select the Tools->Delete Fake PKI and Tools->Delete Fake Keys to ensure new keys and artifacts will be generated. Select Tools->Delete all fake items if there are no custom configurations you wish to retain (do not choose this option is generating other than RSA 2048).
3. Make sure all options on the Options->Preferences->Basic Generation Options tab are unchecked. Otherwise, some negative test cases may not be accurately cloned.
4. Select the Tools->Generate PKI menu item to generate new key pairs and signed artifacts. 
5. Wait (key generation will take some time).
6. Save the PCP database (possible via Save As to provide a name indicative of algorithm orientation of clones).
7. Review the Has Fake column on the Certificates and CRLs tabs and confirm all artifacts have been cloned. If not, review logs, determine cause, correct the issue and retry.
8. Select the Tools->Export PKI menu item.
9. Rename exported folder to indicate nature of cloned artifacts, if desired.
10.	Copy contents of fake folder beneath configured CRL folder to the exported folder, if desired.
11.	Generate a copy of the cloned artifacts using the original file names using the ClonedPkitsNameFixer tool along with original PKITS data, cloned data and a folder to receive renamed artifacts.

```
mkdir <path>/PKITS_<alg>/renamed 
python ClonedPkitsNameFixer.py -a /<path>/1.0.1/PKITS_data -b /<path>/PKITS_<alg> -c /<path>/PKITS_<alg>/renamed
```
12.	Break the signatures on necessary artifacts using the BreakSig utility

```
python BreakSig.py -i /Users/cwallace/Desktop/SCVP_artifacts/PKITS_<alg>_renamed/
```
##### 2.1.2.3	Customizing generation rules for RSA-2048

No customization rules are required. Open the database prepared in section 2.1.2.1 then save a copy of the database using a name that indicates RSA2048 orientation. Next, simply execute the steps from 2.1.2.2.

##### 2.1.2.4	Customizing generation rules for RSA-4096

Open the database prepared in section 2.1.2.1 then save a copy of the database using a name that indicates RSA4096 orientation.

Navigate to the Generator Configuration tab then to the Algorithm Map sub-tab. In the Mapped Algorithm column, choose “Algorithm rsaEncryption; Key size: 4096; Exponent: 0x010001” as the mapped value for “Algorithm rsaEncryption; Key size: 2048; Exponent: 0x010001”, which should be the only item in the Original Algorithm column.

Save the database then execute the steps in section 2.1.2.2. Note, key generation for RSA 4096 bit keys is extremely slow. 

2.1.2.5	Customizing generation rules for ECDSA p256

Open the database prepared in section 2.1.2.1 then save a copy of the database using a name that indicates EC p256 orientation.

Navigate to the Generator Configuration tab then to the Algorithm Map sub-tab then Public key algorithms. In the Mapped Algorithm column, choose “Algorithm id_ecPublicKey; Key size: 256; Curve: secp256r1” as the mapped value for “Algorithm rsaEncryption; Key size: 2048; Exponent: 0x010001”, which should be the only item in the Original Algorithm column. Change the Type to Digital signature algorithms and choose “ecdsa_with_SHA256” in the Mapped Algorithm column for the “Algorithm: sha256WithRSAEncryption; Parameters: present” option, which should be the only item in the Original Algorithm column.

Save the database then execute the steps in section 2.1.2.2.

2.1.2.6	Customizing generation rules for ECDSA p384
Open the database prepared in section 2.1.2.1 then save a copy of the database using a name that indicates EC p384 orientation.

Navigate to the Generator Configuration tab then to the Algorithm Map sub-tab. In the Mapped Algorithm column, choose “Algorithm id_ecPublicKey; Key size: 384; Curve: secp384r1” as the mapped value for “Algorithm rsaEncryption; Key size: 2048; Exponent: 0x010001”, which should be the only item in the Original Algorithm column. Change the Type to Digital signature algorithms and choose “ecdsa_with_SHA384” in the Mapped Algorithm column for the “Algorithm: sha256WithRSAEncryption; Parameters: present” option, which should be the only item in the Original Algorithm column.

Save the database then execute the steps in section 2.1.2.2.

2.1.3	Outputs
The result will include a complete set of PKITS artifacts with names that match the original filenames for each algorithm target elected. If each of sections 2.1.2.3-2.1.2.6 is executed, four sets of artifacts will result. 

2.2	PDTS

2.2.1	Inputs
The PKITS_data.zip file from http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html will provide certificates and CRLs that will be input into PCP to facilitate harvesting then cloning. The bulk of PDTS is focused on LDAP. Since LDAP is not a target for the SCVP testring program, these artifacts need not be cloned. The following artifacts will be cloned (all other artifacts will be omitted):

•	BasicHTTPURIPathDiscoveryOU1EE1.crt
•	BasicHTTPURIPathDiscoveryOU1EE2.crt
•	BasicHTTPURIPathDiscoveryOU1EE3.crt
•	BasicHTTPURIPathDiscoveryOU1EE4.crt
•	BasicHTTPURIPathDiscoveryOU1EE5.crt
•	BasicHTTPURIPathDiscoveryOU3EE1.crt
•	BasicHTTPURIPathDiscoveryOU3EE2.crt
•	BasicHTTPURIPathDiscoveryOrg2EE1.crt
•	BasicHTTPURIPathDiscoveryOrg2EE2.crt
•	BasicHTTPURIPathDiscoveryOrg2EE3.crt
•	BasicHTTPURIPathDiscoveryOrg2EE4.crt
•	BasicHTTPURIPathDiscoveryOrg2EE5.crt
•	BasicHTTPURIPathDiscoveryTest2EE.crt
•	BasicHTTPURIPathDiscoveryTest4EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest13EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest14EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest15EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest16EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest2EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest4EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest7EE.crt
•	RudimentaryHTTPURIPathDiscoveryTest8EE.crt
•	BasicHTTPURITrustAnchorRootCert.crt

As with PKITS, since S/MIME is not a target for the SCVP testing program, the smime folder can be ignored entirely.

2.2.2	Generation Procedures

2.2.2.1	Preparing PDTS for cloning

To prepare a PDTS data set for cloning, perform the following steps.

1)	Download PathDiscoveryTestSuite.zip
2)	Extract the zip file
3)	Use PkitsPdtsReduction utility to omit LDAP artifacts
a.	python PkitsPdtsReduction.py -d <path to extracted zip>
4)	Clean the CRLs folders used by PCP to store “real” CRLs and “fake” CRLs. The location is specified in Options->Preferences->CRLs folder. Delete the contents of the real and fake directories beneath the location identified in the CRL folder setting.
5)	Optionally, delete log file (location specified in the dialog accessed via Options->Preferences->LoggingConfiguration->Create/edit/view configuration).
6)	Create a new PCP database (File->New PCP Database)
7)	Import PDTS end entity certificates by navigating to the Certificates tab and clicking the Import Certificates button and browsing to the “End Entity Certs” folder within the reduced “Path Discovery Test Suite” folder. 22 certificates should be imported.
8)	Import PDTS trust anchor certificates by navigating to the Certificates tab and clicking the Import Certificates button and browsing to the “Trust Anchor Certs” folder within the reduced “Path Discovery Test Suite” folder. 1 additional certificate should be imported resulting in 23 certificates total.
9)	Save the PCP database.
10)	Make sure both Recursive URI harvest and Skip LDAP URIs during harvest are checked. Harvest additional certificates by clicking the Harvest certificates from URIs button on the Certificates tab. 82 certificates should be present, along with 42 PKCS #7 messages.
11)	Navigate to the CRLs tab. Make sure Skip LDAP URIs during harvest is checked the click Harvest CRLs to harvest CRLs. 28 CRLs should be retrieved.
12)	Save the PCP database.
13)	Close the PCP database.

2.2.2.2	Basic PDTS clone generation

To prepare a cloned PDTS data set, perform the following steps:

1)	Open the PCP database prepared in section 2.2.2.1.
2)	Select the Tools->Delete Fake PKI and Tools->Delete Fake Keys to ensure new keys and artifacts will be generated. Select Tools->Delete all fake items if there are no custom configurations you wish to retain.
3)	Navigate to the Generator Configuration tab. On the Hosts sub-tab select the URI name form. Click the Append default suffix to each button. Enter test into the resulting dialog and click OK. The names from the left column should now appear in the right column with a .test suffix appending. There is no need to alter the RFC822 domain and are no other hosts listed for other name forms.
4)	Make sure the first two options on the Options->Preferences->Basic Generation Options tab are checked. This will ensure expired certificates and stale CRLs are refreshed. This is a necessary step because PDTS was never updated by NIST after the initial data set expired.
5)	Select the Tools->Generate PKI menu item to generate new key pairs and signed artifacts. 
6)	Wait (key generation will take some time).
7)	Save the PCP database (possible via Save As to provide a name indicative of algorithm orientation of clones).
8)	Review the Has Fake column on the Certificates and CRLs tabs and confirm all artifacts have been cloned. If not, review logs, determine cause, correct the issue and retry.
9)	Select the Tools->Export PKI menu item.
10)	Rename exported folder to indicate nature of cloned artifacts, if desired.
11)	Copy contents of fake folder beneath configured CRL folder to the exported folder, if desired.
12)	Generate a copy of the cloned artifacts using the original file names using the ClonedPkitsNameFixer tool along with original PDTS data, cloned data and a folder to receive renamed artifacts.
a.	mkdir <path>/PDTS/renamed 
b.	python ClonedPkitsNameFixer.py -d “/<path>/Path Discovery Test Suite” -e /<path>/PDTS -f /<path>/PDTS/renamed
c.	Delete spurious folders created with names of PKITS path settings
13)	Export and save a list of hosts using the Analysis->Reports->List hosts menu item.

2.2.3	Outputs
The result will include a complete set of PDTS artifacts with names for end entity and trust anchor certificates that match the original filenames. These materials can be used to prepare a VM hosting the artifacts.

2.3	MFPKI

2.3.1	Inputs

A set of 58 end entity certificates from various PKIs connected to the FPKI will be provided as input to PCP along with a p7b file containing all certificates collected by the FPKI crawler (available from https://fpki-graph.fpki-lab.gov/crawler/) to facilitate harvesting then cloning.

2.3.2	Generation Procedures

2.3.2.1	Preparing MFPKI for cloning

To prepare a MFPKI data set for cloning, perform the following steps.

1)	Collect the desired end entity certificates beneath a single folder (there may be sub-folders) and download the latest FPKI crawler p7b file.
2)	Clean the CRLs folders used by PCP to store “real” CRLs and “fake” CRLs. The location is specified in Options->Preferences->CRLs folder. Delete the contents of the real and fake directories beneath the location identified in the CRL folder setting.
3)	Optionally, delete log file (location specified in the dialog accessed via Options->Preferences->Logging Configuration->Create/edit/view configuration).
4)	Create a new PCP database (File->New PCP Database)
5)	Import MFPKI end entity certificates by navigating to the Certificates tab and clicking the Import Certificates button and browsing to the folder containing the end entity certificates collected in step 1. Confirm the number of certificates that were imported matches expectations.
6)	Import the CA certificates from the FPKI crawler by navigating to the PKCS7 Messages tab, clicking the Import PKCS7 File… button and browsing to the CACertificatesValidatingToFederalCommonPolicy.p7b file.
7)	Save the PCP database.
8)	Make sure both Recursive URI harvest and Skip LDAP URIs during harvest are checked. Harvest additional certificates by clicking the Harvest certificates from URIs button on the Certificates tab. After that completes, click the Harvest OCSP responder certificates button.
9)	Navigate to the CRLs tab. Make sure Skip LDAP URIs during harvest is checked the click Harvest CRLs to harvest CRLs. 
10)	Save the PCP database.
11)	Close the PCP database.

2.3.2.2	Basic MFPKI clone generation

To prepare a cloned MFPKI data set, perform the following steps:

1)	Open the PCP database prepared in section 2.2.2.1.
2)	Select the Tools->Delete Fake PKI and Tools->Delete Fake Keys to ensure new keys and artifacts will be generated. Select Tools->Delete all fake items if there are no custom configurations you wish to retain.
3)	Navigate to the Generator Configuration tab. On the Hosts sub-tab select the URI name form. Click the Append default suffix to each button. Enter test into the resulting dialog and click OK. The names from the left column should now appear in the right column with a .test suffix appending. There is no need to alter the RFC822 or other name forms since testing these name forms is not planned and these name forms have no hosting component.
4)	Navigate to the Basic Generator Configuration sub-tab. Make sure cn=default is selected as the Configuration Name then click the Generate configuration for selected configuration option. Click all four check boxes associated with alterations to cause end entity personal information to be altered.
5)	Make sure the first two options on the Options->Preferences->Basic Generation Options tab are checked. This will ensure expired certificates and stale CRLs are refreshed. 
6)	Navigate to the DN Map sub-tab. Go through the list and for each top level RDN (i.e., c=US, c=CA, dc=com, etc.) modify the name to indicate a test certificate by adding either o=Mock or dc=Mock adjacent to the terminal RDN.
7)	Select the Tools->Generate PKI menu item to generate new key pairs and signed artifacts.
8)	Wait (key generation will take some time).
9)	Save the PCP database (possible via Save As to provide a name indicative of algorithm orientation of clones).
10)	Review the Has Fake column on the Certificates and CRLs tabs and confirm all artifacts have been cloned. If not, review logs, determine cause, correct the issue and retry.
11)	Select the Tools->Export PKI menu item.
12)	Rename exported folder to indicate nature of cloned artifacts, if desired.
13)	Copy contents of fake folder beneath configured CRL folder to the exported folder, if desired. 
14)	Export and save a list of hosts using the Analysis->Reports->List hosts menu item.

2.3.3	Outputs

The result will include a complete set of PDTS artifacts with names for end entity and trust anchor certificates that match the original filenames. These materials can be used to prepare a VM hosting the artifacts.

Appendix A - Python Virtual Environment creation

Several of the tools used to prepare the SCVP test artifacts are written in Python. The tools have minimal dependencies and can be run in a relatively bare bones Python 3 virtual environment. The following steps was used on an OS X system with Python 3 installed in /usr/local/bin.

/usr/local/bin/virtualenv pcpvenv --python=python3

The following step can be used to activate the virtual environment.

source pcpvenv/bin/activate

Install the glob2 package using the following command.

pip install glob2

Appendix B - Resigning PKITS certificates with bad signatures

PCP uses signatures to organize artifacts for cloning. In order for certificates with bad signatures to be successfully cloned, the artifacts must first be resigned. This will enable PCP to generate a clone. Signatures can be broken on the cloned artifacts using the BreakSig.py script.

Two certificates require resigning, which requires extracting private keys for two different CAs. The following examples illustrate how to extract PKCS #8 keys from the PKCS #12 objects included with PKITS then using ResignCert to generate resigned artifacts suitable for cloning. 

openssl pkcs12 -in TrustAnchorRootCertificate.p12 -nodes 
-out TrustAnchorRootCertificate.pem

openssl pkcs8 -topk8 -inform PEM -outform DER 
-in TrustAnchorRootCertificate.pem 
-out TrustAnchorRootCertificate.p8 -nocrypt

openssl pkcs12 -in GoodCACert.p12 -nodes 
-out GoodCACert.pem

openssl pkcs8 -topk8 -inform PEM -outform DER 
-in GoodCACert.pem -out GoodCACert.p8 -nocrypt


ResignCert.exe -p TrustAnchorRootCertificate.p8 
-i BadSignedCACert.crt -o .\BadSignedCACert.resigned.crt

ResignCert.exe -p GoodCACert.p8 
-i InvalidEESignatureTest3EE.crt 
-o .\InvalidEESignatureTest3EE.resigned.crt

After generating resigned artifacts, rename thee original files with a .omit file extension.

