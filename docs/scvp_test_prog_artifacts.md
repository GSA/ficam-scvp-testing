---
layout: default
title: Generating SCVP Test Program Artifacts - Step-by-Step Guide
permalink: /scvpartifactsguide/
---

### Revision History 

Date|Version|Changes|
:---:|:---:|---|
08/08/2017|1.0|Final Publication|

### Table of Contents **REMEMBER TO ADD "BACK TO TABLE OF CONTENTS" LINK AFTER SECTIONS**

**ADD TOC IN + a bunch of Appendices**

## 1 Overview

This document describes the test artifacts that will be generated and used as part of the U.S. General Services Administration's (GSA) Server-based Certificate Validation Protocol (SCVP) Test Program (GSTP). The GSTP's goal is to confirm whether an SCVP Responder is capable of providing accurate certification path validation results in environments with comparable complexity to the U.S. Federal Public Key Infrastructure (FPKI). <!--Added goal statement here from user's guide to give more complete information.-->

Three distinct sets of test artifacts will be used to test certification path development and certification path validation capabilities: <!--Added purpose statement here from user's guide to give more complete information.-->

1. NIST’s Public Key Infrastructure (PKI) Interoperability Test Suite v2 (PKITSv2)
2. NIST’s Path Development Test Suite v2 (PDTSv2)
3. Mock-Federal PKI (MFPKI)<!--Test Suite?-->

The remainder of this document describes the **||nature||** of each artifact set and the procedures needed to generate the artifacts. These artifacts are generated using the PKI Copy and Paste (PCP) utility. For PKITS, PCP is used to generate the test artifacts containing algorithms and key sizes other than RSA-2048. For PDTS, PCP is used to refresh an expired test suite and to modify the URLs used for hosting. For MFPKI, PCP is used to generate artifacts of comparable complexity to the production FPKI. The following table describes the targeted PKITS and PDTS Test Suites:

Test Suite|Public Key Details|Hash Algorithm|Hosting Strategy|
---|:---:|:---:|:---|
PKITS|RSA-2048|SHA256|Not hosted; zip file|
PKITS|RSA-4096|SHA256|Not hosted; zip file|
PKITS|EC P-256|SHA256|Not hosted; zip file|
PKITS|EC P-384|SHA384|Not hosted; zip file|
PDTS|RSA-2048|SHA256|Downloadable VM|
PDTS|RSA-2048|SHA256|CITE-hosted|

> **Note:**&nbsp;&nbsp;The PKITS and PDTS varieties are not intended to be used simultaneously. Artifacts from one data set bear a strong resemblance to the corresponding artifacts in another data set. Each variety should be tested in isolation from the others.

## 2 Test Artifacts

### 2.1	Public Key Infrastructure (PKI) Interoperability Test Suite (PKITS)

#### 2.1.1 Inputs

The `PKITS_data.zip` file from [NIST Public Key Infrastructure Testing](https://csrc.nist.gov/projects/pki-testing){:target="_blank"}_ provides certificates and CRLs that will be input into PCP to facilitate cloning. (At the NIST website, see the **Path Validation Testing Program** section and click on the _test data_ link.) Because Digital Signature Algorithm (DSA) will not be used in the SCVP Test Program, the following artifacts will not be cloned and can be omitted from the input data:

*	`DSACACert.crt`
*	`DSAParametersInheritedCACert.crt`
*	`InvalidDSASignatureTest6EE.crt`
*	`ValidDSAParameterInheritanceTest5EE.crt`
*	`ValidDSASignaturesTest4EE.crt`
*	`DSACACRL.crl`
*	`DSAParametersInheritedCACRL.crl`

Additionally, since neither Lightweight Directory Access Protocol (LDAP) nor S/MIME is a target for the SCVP Test Program, the `certpairs` and `smime` folders can be ignored entirely.

Two certificate objects must be resigned prior to cloning. These artifacts are: `InvalidEESignatureTest3EE.crt` and `BadSignedCACert.crt`. `GoodCACert.p12` and `TrustAnchorRootCertificate.p12` sign these artifacts, respectively. (See _Appendix B_ for the steps to extract Public-Key Cryptography Standard (PKCS) #8 keys from the PKCS #12 files and resign the two certificate files. This step needs to be performed only once, with the altered data set used as input to each cloning operation.) 

#### 2.1.2 Generation Procedures

##### 2.1.2.1	Preparing PKITS for cloning

> **Note:**&nbsp;&nbsp;Steps 1-3 apply when using NIST’s PKITS edition. (See _Appendix F_ for details on PKITSv2 data set [i.e., PKITS with Authority Information Access (AIA) and Certificate Revocation List (CRL) Distribution (DP) extensions].)

To prepare a PKITS data set for cloning, perform the following steps:

1. Download the `PKITS_data.zip`. 
2. Extract the zip file.
3. Resign the necessary artifacts (`InvalidEESignatureTest3EE.crt` and `BadSignedCACert.crt`) using the steps given in _Appendix B_.
4. Use the `PkitsPdtsReduction` utility to omit the DSA artifacts:&nbsp;&nbsp;`python PkitsPdtsReduction.py -v` (path to extracted zip).
5. Clean the CRLs folders used by PCP to store “real” CRLs and “fake” CRLs. (The location is specified in **_Options_ &gt; _Preferences_ &gt; _CRLs_** folder.) Delete the contents of the "real" and "fake directories beneath the location identified in the CRL folder setting.
6. Optionally, delete the log file (location specified in the dialog box accessed via **_Options_ &gt; _Preferences_ &gt; _LoggingConfiguration_ -&gt; _Create/edit/view_** configuration). 
7. Create a new PCP database: **_File_ &gt; _New PCP Database_**.
8. Import PKITS certificates by navigating to the **_Certificates_** tab and clicking the **_Import Certificates_** button and browsing to the certs folder within the reduced PKITS_data folder. (**Note:**&nbsp;nbsp;400 certificates should be imported.)
9. Find the _Invalid Missing basicConstraints EE Certificate Test 1_ certificate (certificate hash value `F5042289168F331674FCEE68D4170A0A640588D6`) and delete it. Click **_Import Certificate_** and browse to the `InvalidMissingbasicConstraintsTest1EE.crt` to re-import it. (This is necessary to establish the relationship to a certificate that was not imported as a Certification Authority [CA].)
10.	Import PKITS CRLs by navigating to the **_CRLs_** tab and clicking the **_Import CRLs_** button and browsing to the crls folder within the reduced `PKITS_data` folder. (This will simply copy the files to the real folder beneath the configured CRL folder.) A total of 171 CRLs should be imported.
11. Save the PCP database and close it.

##### 2.1.2.2	Basic PKITS clone generation

To prepare a cloned PKITS data set, perform the following steps:

1. Open the PCP database prepared per section 2.1.2.1 and altered via any customizations from sections 2.1.2.3 through 2.1.2.6.
2. Select the **_Tools_ &gt; _Delete Fake PKI_** and **_Tools_ &gt; _Delete Fake Keys_** to ensure new keys and artifacts will be generated. Select **_Tools_ &gt; _Delete all fake items_** if there are no custom configurations you wish to retain. (Do not choose this option if generating other than RSA-2048.)
3. Make sure all options on the **_Options_ &gt; _Preferences_ &gt; _Basic Generation Options_** tab are _unchecked_. Otherwise, some negative test cases may not be accurately cloned.
4. Select the **_Tools_ &gt; _Generate PKI_** menu item to generate new key pairs and signed artifacts. 
5. Wait. (Key generation will take some time.)
6. Save the PCP database (possible via **_Save As_** to provide a name indicative of algorithm orientation of clones).
7. Review the **_Has Fake_** column on the Certificates and CRLs tabs and confirm that all artifacts have been cloned. If not, review logs, determine cause, correct the issue, and retry.
8. Select the **_Tools_ &gt; _Export PKI_** menu item.
9. Rename exported folder to indicate the nature of cloned artifacts, if desired.
10.	Copy the contents of the fake folder beneath the configured CRL folder to the exported folder, if desired.
11.	Generate a copy of the cloned artifacts (using the original file names) using the `ClonedPkitsNameFixer` tool along with original PKITS data, cloned data, and a folder to receive renamed artifacts.

```
a. mkdir <path>/PKITS_<alg>/renamed 
b. python ClonedPkitsNameFixer.py -a /<path>/1.0.1/PKITS_data -b /<path>/PKITS_<alg> -c /<path>/PKITS_<alg>/renamed
```
12.	Break the signatures on necessary artifacts using the `BreakSig` utility:

```
a. python BreakSig.py -i /Users/cwallace/Desktop/SCVP_artifacts/PKITS_<alg>_renamed/
```
##### 2.1.2.3	Customizing generation rules for RSA-2048

No customization rules are required. Open the database prepared in section 2.1.2.1 and then save a copy of the database using a name that indicates RSA-2048 orientation. Next, simply execute the steps from section 2.1.2.2.

##### 2.1.2.4	Customizing generation rules for RSA-4096

1. Open the database prepared in section 2.1.2.1 and then save a copy of the database using a name that indicates RSA-4096 orientation.
2. Navigate to the **_Generator Configuration_** tab and then to the Algorithm Map sub-tab. 
3. In the **Mapped Algorithm** column, choose _“Algorithm rsaEncryption; Key size: 4096; Exponent: 0x010001”_ as the mapped value for _“Algorithm rsaEncryption; Key size: 2048; Exponent: 0x010001”,_ which should be the only item in the **_Original Algorithm_** column.
4. Save the database and then execute the steps in section 2.1.2.2. (**Note:**&nbsp;&nbsp;Key generation for RSA-4096 bit keys is extremely slow.) 

##### 2.1.2.5	Customizing generation rules for ECDSA p256

1. Open the database prepared in section 2.1.2.1 and then save a copy of the database using a name that indicates EC p256 orientation.
2. Navigate to the **_Generator Configuration_** tab **&gt;** **_Algorithm Map_** sub-tab **&gt;** **_Public key algorithms_**. 
3. In the **_Mapped Algorithm_** column, choose “_Algorithm id_ecPublicKey; Key size: 256; Curve: secp256r1_” as the mapped value for “_Algorithm rsaEncryption; Key size: 2048; Exponent: 0x010001_”, which should be the only item in the **_Original Algorithm_** column. 
4. Change the **_Type_** to _Digital signature algorithms_, and choose “_ecdsa_with_SHA256_” in the **_Mapped Algorithm_** column for the “_Algorithm: sha256WithRSAEncryption; Parameters: present_” option, which should be the only item in the **_Original Algorithm_** column.
5. Save the database then execute the steps in section 2.1.2.2.

##### 2.1.2.6	Customizing generation rules for ECDSA P384

1. Open the database prepared in section 2.1.2.1 and then save a copy of the database using a name that indicates EC p384 orientation.
2. Navigate to **_Generator Configuration_** tab **&gt;** **_Algorithm Map_** sub-tab. 
3. In the **_Mapped Algorithm_** column, choose “_Algorithm id_ecPublicKey; Key size: 384; Curve: secp384r1_” as the mapped value for “_Algorithm rsaEncryption; Key size: 2048; Exponent: 0x010001_”, which should be the only item in the **_Original Algorithm_** column. 
4. Change the **_Type_** to _Digital signature algorithms_ and choose “_ecdsa_with_SHA384_” in the **_Mapped Algorithm_** column for the “_Algorithm: sha256WithRSAEncryption; Parameters: present_” option, which should be the only item in the **_Original Algorithm_** column.
5. Save the database then execute the steps in section 2.1.2.2.

#### 2.1.3	Outputs

The results will include a complete set of PKITS artifacts with names that match the original filenames for each algorithm target elected. If each of sections 2.1.2.3 through 2.1.2.6 is executed, four sets of artifacts will result. 

### 2.2	Path Development Test Suite (PDTS)

2.2.1	Inputs

The `PKITS_data.zip` file from [NIST Public Key Infrastructure Testing](https://csrc.nist.gov/projects/pki-testing){:target="_blank"}_ provides certificates and CRLs that will be input into PCP to facilitate harvesting and then cloning. (At the NIST website, see the **Path Validation Testing Program** section and click on the _test data_ link.) The bulk of PDTS is focused on LDAP. Since LDAP is not a target for the SCVP Test Program, these artifacts need not be cloned. The following artifacts will be cloned (all other artifacts will be omitted):

*	`BasicHTTPURIPathDiscoveryOU1EE1.crt`
*	`BasicHTTPURIPathDiscoveryOU1EE2.crt`
*	`BasicHTTPURIPathDiscoveryOU1EE3.crt`
*	`BasicHTTPURIPathDiscoveryOU1EE4.crt`
*	`BasicHTTPURIPathDiscoveryOU1EE5.crt`
*	`BasicHTTPURIPathDiscoveryOU3EE1.crt`
*	`BasicHTTPURIPathDiscoveryOU3EE2.crt`
*	`BasicHTTPURIPathDiscoveryOrg2EE1.crt`
*	`BasicHTTPURIPathDiscoveryOrg2EE2.crt`
*	`BasicHTTPURIPathDiscoveryOrg2EE3.crt`
*	`BasicHTTPURIPathDiscoveryOrg2EE4.crt`
*	`BasicHTTPURIPathDiscoveryOrg2EE5.crt`
*	`BasicHTTPURIPathDiscoveryTest2EE.crt`
*	`BasicHTTPURIPathDiscoveryTest4EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest13EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest14EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest15EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest16EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest2EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest4EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest7EE.crt`
*	`RudimentaryHTTPURIPathDiscoveryTest8EE.crt`
*	`BasicHTTPURITrustAnchorRootCert.crt`

As with PKITS, since S/MIME is not a target for the SCVP testing program, the S/MIME folder can be ignored entirely.

#### 2.2.2	Generation Procedures

##### 2.2.2.1	Preparing PDTS for cloning

To prepare a PDTS data set for cloning, perform the following steps:

1. Download `PathDiscoveryTestSuite.zip`
2. Extract the zip file
3. Use PkitsPdtsReduction utility to omit LDAP artifacts
```
python PkitsPdtsReduction.py -d <path to extracted zip>
```
4. Clean the CRLs folders used by PCP to store “real” CRLs and “fake” CRLs. The location is specified in **_Options_ &gt; _Preferences_ &gt; _CRLs_** folder. Delete the contents of the "real" and "fake" directories beneath the location identified in the CRL folder setting.
5. Optionally, delete the log file (location specified in the dialog box accessed via **_Options_ &gt; _Preferences_ &gt; _LoggingConfiguration_ &gt; _Create/edit/view_** configuration).
6. Create a new PCP database: **_File_ &gt; _New PCP Database_**.
7. Import _PDTS end-entity certificates_ by navigating to the **_Certificates_** tab, clicking the **_Import Certificates_** button, and browsing to the **_“End Entity Certs”_** folder within the reduced **_“Path Discovery Test Suite”_** folder. A total of 22 certificates should be imported.
8. Import _PDTS trust anchor certificates_ by navigating to the **_Certificates_** tab, clicking the **_Import Certificates_** button, and browsing to the _“Trust Anchor Certs”_ folder within the reduced _“Path Discovery Test Suite”_ folder. One additional certificate should be imported, resulting in 23 certificates total.
9. Save the PCP database.
10. Make sure both _Recursive URI harvest_ and _Skip LDAP URIs during harvest_ are checked. Harvest additional certificates by clicking the _Harvest_ certificates from the **_URIs_** button on the **_Certificates_** tab. A total of 82 certificates should be present, along with 42 PKCS #7 messages.
11. Navigate to the **_CRLs_** tab. Make sure that _Skip LDAP URIs during harvest_ is checked and then click **_Harvest CRLs_** to harvest CRLs. A total of 28 CRLs should be retrieved.
12. Save the PCP database and close it.

##### 2.2.2.2	Basic PDTS clone generation

To prepare a cloned PDTS data set, perform the following steps:

1. Open the **_PCP database_** prepared in section 2.2.2.1.
2. Select the **_Tools_ &gt; _Delete Fake PKI_** and **_Tools_ &gt; _Delete Fake Keys_** to ensure new keys and artifacts will be generated. Select **_Tools_ &gt; _Delete all fake items_**, if there are no custom configurations you wish to retain.
3. Navigate to the **_Generator Configuration_** tab. On the **_Hosts_** sub-tab, select the **_URI_** name form. Click the _Append_ default suffix to each button. Enter _test_ into the resulting dialog and click OK. The names from the left column should now appear in the right column with a _.test_ suffix appended. There is no need to alter the RFC 822 domain, and there are no other hosts listed for other name forms.
4. Make sure that the first two options on the **_Option_ &gt; _Preferences_ &gt; _Basic Generation Options_** tab are checked. This will ensure expired certificates and stale CRLs are refreshed. This is a necessary step because PDTS was never updated by NIST after the initial data set expired.
5. Select the **_Tools_ &gt; _Generate PKI_** menu item to generate new key pairs and signed artifacts. 
6. Wait. (Key generation will take some time.)
7. Save the _PCP database_ (via _Save As_ to provide a name indicative of algorithm orientation of clones).
8. Review the **_Has Fake_** column on the **_Certificates_** and **_CRLs_** tabs and confirm that all artifacts have been cloned. If not, review logs, determine cause, and correct the issue and retry.
9. Select the **_Tools_ &gt; _Export PKI_** menu item.
10. Rename the exported folder to indicate the nature of cloned artifacts, if desired.
11. Copy the contents of the **_Fake_** folder beneath the configured **_CRL_** folder to the exported folder, if desired.
12.	Generate a copy of the cloned artifacts using the original file names by using the **_ClonedPkitsNameFixer_** tool, along with original PDTS data, cloned data and a folder to receive renamed artifacts.

```
mkdir <path>/PDTS/renamed
python ClonedPkitsNameFixer.py -d “/<path>/Path Discovery Test Suite” -e /<path>/PDTS -f /<path>/PDTS/renamed
```
13. Delete spurious folders created with names of PKITS path settings.
14. Export and save a list of hosts using the **Analysis_ &gt; _Reports_ &gt; _List hosts** menu item.

#### 2.2.3 Outputs

The results will include a complete set of PDTS artifacts with names for end entity and trust anchor certificates that match the original filenames. These materials can be used to prepare a VM hosting of the artifacts.

### 2.3	MFPKI

#### 2.3.1 Inputs

A set of 58 end entity certificates from various PKIs connected to the FPKI will be provided as inputs to PCP along with a .p7b file containing all certificates collected by the [FPKI Crawler](https://fpki-graph.fpki-lab.gov/crawler/){:target=_"blank"} to facilitate harvesting and then cloning.

#### 2.3.2	Generation Procedures

##### 2.3.2.1	Preparing MFPKI for cloning

To prepare a MFPKI data set for cloning, perform the following steps:

1. Collect the desired end entity certificates beneath a single folder (there may be sub-folders) and download the latest FPKI Crawler .p7b file.
2. Clean the **_CRLs_** folders used by PCP to store “real” CRLs and “fake” CRLs. The location is specified in the **_Options_ &gt; _Preferences_ &gt; _CRLs_** folder. Delete the contents of the "real" and "fake" directories beneath the location identified in the **_CRL_** folder setting.
3. Optionally, delete log file (location specified in the dialog accessed via **_Options_ &gt; _Preferences_ &gt; _Logging Configuration_ &gt; _Create/edit/view configuration_**).
4. Create a new **_PCP database_** (**_File_ &gt; _New PCP Database_**)
5. Import MFPKI end entity certificates by navigating to the **_Certificates_** tab; clicking the **_Import Certificates_** button; and browsing to the folder containing the end entity certificates collected in Step 1. Confirm that the number of certificates that were imported matches expectations.
6. Import the CA certificates from the FPKI Crawler by navigating to the **_PKCS7 Messages_** tab; clicking the **_Import PKCS7 File…_** button; and browsing to the _CACertificatesValidatingToFederalCommonPolicy.p7b_ file.
7. Save the **_PCP database_**.
8. Make sure both **_Recursive URI harvest_** and **_Skip LDAP URIs during harvest_** are checked. Harvest additional certificates by clicking the **_Harvest certificates from URIs_** button on the **_Certificates_** tab. After that completes, click the **_Harvest OCSP responder certificates_** button.
9. Navigate to the **_CRLs_** tab. Make sure that **_Skip LDAP URIs during harvest_** is checked and then click **_Harvest CRLs_** to harvest the CRLs. 
10. Save and then close the **_PCP database_**.

##### 2.3.2.2	Basic MFPKI clone generation

**CELESTE STOPPED HERE**

To prepare a cloned MFPKI data set, perform the following steps:

1. Open the **_PCP database_** prepared in section 2.2.2.1.
2. Select the **Tools &gt; Delete Fake PKI** and **Tools &gt; Delete Fake Keys** to ensure that new keys and artifacts will be generated. If there are no custom configurations you wish to retain, select **Tools &gt; Delete all fake items**.
3. Navigate to the **Generator Configuration** tab. On the **Hosts** sub-tab, select the _URI name form_. Click the _Append default suffix_ to each button. Enter _test_ into the resulting dialog and click **OK**. The names from the left-hand column should now appear in the right column with a _.test_ suffix appended. There is no need to alter the RFC822 or other name forms since testing these name forms is not planned and they have no hosting component.
4. Navigate to the **Basic Generator Configuration** sub-tab. Make sure _cn=default_ is selected as the _Configuration Name_ and then click the **Generate configuration for selected configuration** option. Click all four checkboxes associated with alterations to cause end entity personal information to be altered.

**CELESTE STOPPED HERE**

5. Make sure the first two options on the Options->Preferences->Basic Generation Options tab are checked. This will ensure expired certificates and stale CRLs are refreshed. 
6. Navigate to the DN Map sub-tab. Go through the list and for each top level RDN (i.e., c=US, c=CA, dc=com, etc.) modify the name to indicate a test certificate by adding either o=Mock or dc=Mock adjacent to the terminal RDN.
7. Select the Tools->Generate PKI menu item to generate new key pairs and signed artifacts.
8. Wait (key generation will take some time).
9. Save the PCP database (possible via Save As to provide a name indicative of algorithm orientation of clones).
10. Review the Has Fake column on the Certificates and CRLs tabs and confirm all artifacts have been cloned. If not, review logs, determine cause, correct the issue and retry.
11. Select the Tools->Export PKI menu item.
12. Rename exported folder to indicate nature of cloned artifacts, if desired.
13. Copy contents of fake folder beneath configured CRL folder to the exported folder, if desired. 
14. Export and save a list of hosts using the Analysis->Reports->List hosts menu item.

#### 2.3.3	Outputs

The result will include a complete set of PDTS artifacts with names for end entity and trust anchor certificates that match the original filenames. These materials can be used to prepare a VM hosting the artifacts.

## Appendix A - Python Virtual Environment Creation

Several of the tools used to prepare the SCVP test artifacts are written in Python. The tools have minimal dependencies and can be run in a relatively "bare-bones" Python 3 virtual environment. The following steps were used on a Mac OS X system<!--Assume Mac?--> with Python 3 installed in `/usr/local/bin`.

```
/usr/local/bin/virtualenv pcpvenv --python=python3
```
The following step can be used to activate the virtual environment:

```
source pcpvenv/bin/activate
```
Install the glob2 package using the following command.

```
pip install glob2
```
## Appendix B - Resigning PKITS Certificates with Bad Signatures

PCP uses signatures to organize artifacts for cloning. In order for certificates with bad signatures to be successfully cloned, the artifacts must first be resigned. This will enable PCP to generate a clone. Signatures can be broken on the cloned artifacts using the BreakSig.py script.

Two certificates require resigning, which requires extracting private keys for two different CAs. The following examples illustrate how to extract PKCS #8 keys from the PKCS #12 objects included with PKITS then using ResignCert to generate resigned artifacts suitable for cloning. 
```
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
```
After generating resigned artifacts, rename thee original files with a .omit file extension.

## Appendix C - Using PITTv2 to Review Cloned Artifacts

The PKI Interoperability Test Tool version 2 (PITTv2) can be used to verify cloned artifacts. This section describes how to use the tool with the `PKITS.sdb` file provided as a sample. This .sdb file contains certification path validation settings that align with the settings defined in the PKITS documentation. The settings are defined in terms of several artifacts that are assumed to exist. The table below describes these artifacts. The trust anchor store files can all co-exist. The contents of the PKITS_data folder will need to be manually changed depending on the collection being verified. In other words, there is a security environment defined for each PKITS data set but there is only one set of path settings definitions that is shared across PKITS data sets. One could endeavor to define path settings definitions for each data set if desired.

File or Folder Location|Contents|
---|---|
C:\PittSettings\tas\PKITS_RSA_2048.tas|Trust anchor store file containing the TrustAnchorRootCertificate.crt file from the cloned PKITS RSA 2048 collection|
C:\PittSettings\tas\PKITS_RSA_4096.tas|Trust anchor store file containing the TrustAnchorRootCertificate.crt file from the cloned PKITS RSA 4096 collection|
C:\PittSettings\tas\PKITS_EC_p256.tas|Trust anchor store file containing the TrustAnchorRootCertificate.crt file from the cloned PKITS EC p256 collection|
C:\PittSettings\tas\PKITS_EC_p384.tas|Trust anchor store file containing the TrustAnchorRootCertificate.crt file from the cloned PKITS EC p384 collection|
C:\PKITS_data\certificates|CA certificates that align with the target collection being validated|
C:\PKITS_data\crls|CRLs certificates that align with the target collection being validated|

There are two test cases where the PITTv2 result does not match the “expected” result. For test case 4.14.16, PITTv2 does not show an error for a certificate that is on hold. However, it does return this information in the results (i.e., view the path log for this target). For test case 4.14.30, PITTv2 returns an error where the PKITS documentation indicates success should be returned. In this test case, the CRL issuer’s revocation status is determined using a CRL issued by the CRL issuer. PITTv2 does not allow circular dependencies (i.e., a CA may not vouch for itself). With these two caveats in mind, the following table describes the summary results generated by PITTv2 against the PKITS data set.

Settings|No. of Paths|No. of Certificates|No. of Valid pPaths|
---|:---:|:---:|:---:|
Default settings|204|210|92|
Settings 1|4|4|2|
Settings 2|1|1|1|
Settings 3|1|1|0|
Settings 4|2|2|1|
Settings 5|12|12|10|
Settings 6|8|8|5|
Settings 7|1|1|1|
Settings 8|2|2|0|
Settings 9|2|2|0|
Settings 10|1|1|0|

If an artifact set is regenerated, the `.tas` file for that dataset must be updated to include the new trust anchor and to not include the old trust anchor.

## Appendix D - Test SCVP Validation Policy Object Identifiers

Given that the various PKITS data sets are not intended to be comingled, a distinct set of validation policy object identifiers has been defined for each data set for use on SCVP servers configured for testing. 

The validation policies are defined related to Red Hound Software’s OID arc: 1.3.6.1.4.1.37623. An OID has been defined for the SCVP program. Test suites are defined beneath the SCVP program OID with validation policy OIDs beneath the test suite OID.
```
-- 1.3.6.1.4.1.37623.10
id-scvp-testing OBJECT IDENTIFIER ::= { id-redhound 10 }

-- 1.3.6.1.4.1.37623.10.1
id-scvp-valpol OBJECT IDENTIFIER ::= { id-scvp-testing 1 }

-- 1.3.6.1.4.1.37623.10.1.1-4
id-scvp-pkits-2048 OBJECT IDENTIFIER ::= { id-scvp-valpol 1 }
id-scvp-pkits-4096 OBJECT IDENTIFIER ::= { id-scvp-valpol 2 }
id-scvp-pkits-p256 OBJECT IDENTIFIER ::= { id-scvp-valpol 3 }
id-scvp-pkits-p384 OBJECT IDENTIFIER ::= { id-scvp-valpol 4 }
id-scvp-pdts OBJECT IDENTIFIER       ::= { id-scvp-valpol 5 }
id-scvp-mfpki OBJECT IDENTIFIER      ::= { id-scvp-valpol 6 }

-- 1.3.6.1.4.1.37623.10.1.1.0-10
id-scvp-pkits-2048-def OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 0 }
id-scvp-pkits-2048-1 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 1 }
id-scvp-pkits-2048-2 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 2 }
id-scvp-pkits-2048-3 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 3 }
id-scvp-pkits-2048-4 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 4 }
id-scvp-pkits-2048-5 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 5 }
id-scvp-pkits-2048-6 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 6 }
id-scvp-pkits-2048-7 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 7 }
id-scvp-pkits-2048-8 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 8 }
id-scvp-pkits-2048-9 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 9 }
id-scvp-pkits-2048-10 OBJECT IDENTIFIER ::= { id-scvp-pkits-2048 10 }
 
-- 1.3.6.1.4.1.37623.10.1.2.0-10
id-scvp-pkits-4096-def OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 0 }
id-scvp-pkits-4096-1 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 1 }
id-scvp-pkits-4096-2 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 2 }
id-scvp-pkits-4096-3 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 3 }
id-scvp-pkits-4096-4 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 4 }
id-scvp-pkits-4096-5 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 5 }
id-scvp-pkits-4096-6 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 6 }
id-scvp-pkits-4096-7 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 7 }
id-scvp-pkits-4096-8 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 8 }
id-scvp-pkits-4096-9 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 9 }
id-scvp-pkits-4096-10 OBJECT IDENTIFIER ::= { id-scvp-pkits-4096 10 }

-- 1.3.6.1.4.1.37623.10.1.3.0-10
id-scvp-pkits-p256-def OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 0 }
id-scvp-pkits-p256-1 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 1 }
id-scvp-pkits-p256-2 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 2 }
id-scvp-pkits-p256-3 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 3 }
id-scvp-pkits-p256-4 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 4 }
id-scvp-pkits-p256-5 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 5 }
id-scvp-pkits-p256-6 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 6 }
id-scvp-pkits-p256-7 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 7 }
id-scvp-pkits-p256-8 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 8 }
id-scvp-pkits-p256-9 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 9 }
id-scvp-pkits-p256-10 OBJECT IDENTIFIER ::= { id-scvp-pkits-p256 10 }

-- 1.3.6.1.4.1.37623.10.1.4.0-10
id-scvp-pkits-p384-def OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 0 }
id-scvp-pkits-p384-1 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 1 }
id-scvp-pkits-p384-2 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 2 }
id-scvp-pkits-p384-3 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 3 }
id-scvp-pkits-p384-4 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 4 }
id-scvp-pkits-p384-5 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 5 }
id-scvp-pkits-p384-6 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 6 }
id-scvp-pkits-p384-7 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 7 }
id-scvp-pkits-p384-8 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 8 }
id-scvp-pkits-p384-9 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 9 }
id-scvp-pkits-p384-10 OBJECT IDENTIFIER ::= { id-scvp-pkits-p384 10 }

-- 1.3.6.1.4.1.37623.10.1.5.0
id-scvp-pdts-def OBJECT IDENTIFIER ::= { id-scvp-pdts 0 }

-- 1.3.6.1.4.1.37623.10.1.6.0
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 0 }

id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 1 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 2 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 6 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 7 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 8 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 13 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 14 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 15 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 16 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 17 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 18 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 19 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 20 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 36 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 39 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 40 }
id-scvp-mfpki-def OBJECT IDENTIFIER ::= { id-scvp-mfpki 41 }
```

## Appendix E – Re-rooting the MFPKI Using Existing Test Root CA

Before the MFPKI was available, test PKIs were generated using CA products and some combination of manual and automated artifact generation procedures. The trust anchors associated with these efforts are in wide enough use that tying the MFPKI to the existing trust anchors is desirable. This appendix describes steps to identity certificates signed by the cloned Federal Common Policy CA and cloned Federal Bridge CA 2016 so PKCS #10 requests can be generated using XCA to facilitate certificate issuance using the existing CA products.

**<TODO>** **NOTE to Authors:  STEPS ARE MISSING (referred to in previous paragraph).**

## Appendix F – Updating PKITS to feature AIA and CRL DP

NIST’s PKITS test data requires manual presentation of certificates and CRLs to the path validation client. When testing some SCVP servers, the level of effort necessary to manually provision hundreds of certificates and CRLs is quite high. To avoid expending effort on a per-server basis during testing, the PKITS data was recut to feature authorityInformationAccess (AIA) and crlDistributionPoints (CRL DP) extensions to enable responders to automatically retrieve the information. The updated data set can be used as an alternative to the NIST data in [section 2.1.2.1](#section-2.1.2.1).

To prepare the updated data, several new scripts and tools were developed:

*	AddAiaAndCrlDp is a C/C++ command line utility that adds AIAs to certificates and CRLs and CRL DPs to certificates. The `PkitsUpdater.py` script is used to drive the tool.
*	`FetchKeyId` is a C/C++ command line utility that returns an ASCII hexadecimal representation of a SKID or AKID extension in a certificate or CRL.
*	`PkitsUpdater.py` is a Python script that accepts a copy of the NIST PKITS edition and emits a data set containing certificates with appropriate AIAs and CRL DPs, CRLs with appropriate AIAs and a collection of PKCS7 files for hosting as AIA data.

Several additional existing tools were used as well including the ResignCert and ResignCrl utilities built for DISA and the openssl command line utility. 

## Appendix G – Sorting PKITS Data into Folders Based on Expected Results

The test client implements support for the lightweight, long-term and batch profiles defined in the “Treasury Validation Services: SCVP Request and Response Profile” document. The batch option requires support for processing requests containing up to 256 certificates. The MFPKI data set will be used for testing the upper boundary condition (because PKITS and PDTS lack sufficient numbers of end entity certificates). However, the MFPKI data set is intended to consist solely of valid certificates. To test processing a mixture of valid and invalid certificates, the PKITS data set is chunked into folders that indicate the expected results. 

PKITS features 11 different path validation input possibilities. To facilitate exercising batch under different input scenarios, the certificates used within each possibility are subdivided into a folder indicating success is expected and a folder indicating failure is expected.  The PkitsBatchOrganizer.py script is used to chunk data into appropriate folders suitable for use as inputs to the test client during batch testing.

## Appendix H – Tool Inventory

This section describes each of the tools used to produce the data for the test program and for use during testing of products. The list of tools, sources, and purposes is as follows:

Tool|Source|Purpose|
---|---|---|
PKI Copy and Paste (PCP)|Developed by Red Hound for GSA|Used to generate the PKITS, PDTS and MFPKI data sets|
PKI Interoperability Test Tool v2 (PITTv2)|Developed by Red Hound for DISA|Used to test the PKITS, PDTS and MFPKI data sets|
Trust Anchor Store Manager|Developed by Red Hound for DISA|Used to prepare trust anchor stores used by PITTv2|
OpenSSL|OpenSSL Software Foundation|Used by custom Python scripts for various purposes|
ResignCert|Developed by Red Hound for DISA|Used by custom Python scripts to resign certificates|
ResignCrl|Developed by Red Hound for DISA|Used by custom Python scripts to resign CRLs|
XCA|Christian Hohnstadt (from xca.sourceforge.net)|Optionally used to re-root the MFPKI to use an existing test trust anchor|<!--XCA is capitalized according to website.-->

The list of tools, language, and purposes is as follows:

Tool|Language|Purpose|
---|:---:|---|
AddAiaAndCrlDp|C/C++|Used to inject AIA and CRL DP extensions into certificates and AIA extensions into CRLs|
BreakSig|Python|Used to alter signatures on PKITS files associated with bad signature test cases|
ClonedPkitsNameFixer|Python|Used to rename cloned artifacts using name from NIST’s PKITS edition|
FetchKeyId|C/C++|Used to read SKID and AKID extensions in certificates and CRLs
GSTPScriptRunner|Python|Used to run scripts emitted by ScvpScriptGenerator with log rotation
PkitsBatchOrganizer|Python|Used to "chunk" PKITS data into folders based on expected results for a set of path validation inputs|
PkitsPdtsReduction|Python|Used to rename files that will not be cloned (i.e., LDAP PDTS, DSA PKITS)
PkitsSorter|Python|Used to sort PKITS data into folders named with the path validation inputs that are used when validating the certificates
PkitsTableGenerator|C/C++|Used to generate a CSV file with PKITS test cases and expected results enumerated
PkitsUpdater|Python|Used to generate PKITSv2 data set (i.e., PKITS with AIA and CRL DP extensions)
ScvpScriptGenerator|C/C++|Used to generate `bash` scripts that can be used to drive the test client
vss2.jar|Java|Used to test SCVP responders (i.e., Java client based on Treasury’s SCVP code)
