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

This document describes the generation of test artifacts that will be used to as part of GSA’s SCVP testing initiative. Three distinct sets of test artifacts will be employed:

1)	NIST’s Public Key Infrastructure (PKI) Interoperability Test Suite (PKITS)
2)	NIST’s Path Development Test Suite (PDTS)
3)	Mock Federal PKI (MFPKI)

The remainder of this document describes the nature of each artifact set and procedures to generate them. Artifacts are generated using the PKI Copy and Paste (PCP) utility. For PKITS, PCP is used to generate test artifacts containing algorithms and key sizes other than RSA2048. For PDTS, PCP is used to refresh an expired test suite and to modify the URLs used for hosting. For MFPKI, PCP is used to generate artifacts of comparable complexity as the production Federal PKI. The following table describes the target end results.

Test Suite|Public Key Details|Hash Algorithm|Hosting Strategy|
---|:---:|:---:|:---|
PKITS|RSA 2048|SHA256|Not hosted; zip file|
PKITS|RSA 4096|SHA256|Not hosted; zip file|
PKITS|EC p256|SHA256|Not hosted; zip file|
PKITS|EC p384|SHA384|Not hosted; zip file|
PDTS|RSA 2048|SHA256|Downloadable VM|
PDTS|RSA 2048|SHA256|CITE-hosted|

> **Note:**&nbsp;&nbsp;The PKITS and PDTS varieties are not intended to be used simultaneously. Artifacts from one data set bear a strong resemblance to the corresponding artifacts in another data set. Each variety should be tested in isolation of the others

## 2 Test Artifacts

### 2.1	PKITS

#### 2.1.1 Inputs

The PKITS_data.zip file from [NIST Public Key Infrastructure Testing](https://csrc.nist.gov/projects/pki-testing){:target="_blank"} will provide certificates and CRLs that will be input into PCP to facilitate cloning. (At the NIST website, see the **Path Validation Testing Program** section and click on the _test data_ link.) Because DSA will not be used in the SCVP testing program, the following artifacts will not be cloned and can be omitted from the input data:

*	DSACACert.crt
*	DSAParametersInheritedCACert.crt
*	InvalidDSASignatureTest6EE.crt
*	ValidDSAParameterInheritanceTest5EE.crt
*	ValidDSASignaturesTest4EE.crt
*	DSACACRL.crl
*	DSAParametersInheritedCACRL.crl

Additionally, since neither LDAP nor S/MIME is a target for the SCVP testing program, the `certpairs` and `smime` folders can be ignored entirely.

Two certificate objects must be resigned prior to cloning. These artifacts are: InvalidEESignatureTest3EE.crt and BadSignedCACert.crt. GoodCACert.p12 and TrustAnchorRootCertificate.p12 sign these artifacts, respectively. See Appendix B for steps to extract PKCS #8 keys from the PKCS #12 files and resign the two certificate files. This step need be performed just once, with the altered data set used as input to each cloning operation. 

#### 2.1.2 Generation Procedures

##### 2.1.2.1	Preparing PKITS for cloning

> **Note:**nbsp;nbsp;Steps 1-3 apply when using NIST’s PKITS edition. See Appendix F for details on PKITSv2 data set (i.e., PKITS with AIA and CRL DP extensions).

To prepare a PKITS data set for cloning, perform the following steps:

1. Download the `PKITS_data.zip`. 
2. Extract the zip file.
3. Resign the necessary artifacts (InvalidEESignatureTest3EE.crt and BadSignedCACert.crt) using the steps in Appendix B.
4. Use PkitsPdtsReduction utility to omit DSA artifacts:&nbsp;&nbsp;python `PkitsPdtsReduction.py -v` (path to extracted zip).
5. Clean the CRLs folders used by PCP to store “real” CRLs and “fake” CRLs. The location is specified in Options->Preferences->CRLs folder. Delete the contents of the real and fake directories beneath the location identified in the CRL folder setting.
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
##### 2.1.2.3	Customizing generation rules for RSA 2048

No customization rules are required. Open the database prepared in section 2.1.2.1 then save a copy of the database using a name that indicates RSA2048 orientation. Next, simply execute the steps from 2.1.2.2.

##### 2.1.2.4	Customizing generation rules for RSA 4096

Open the database prepared in section 2.1.2.1 then save a copy of the database using a name that indicates RSA4096 orientation.

Navigate to the Generator Configuration tab then to the Algorithm Map sub-tab. In the Mapped Algorithm column, choose “Algorithm rsaEncryption; Key size: 4096; Exponent: 0x010001” as the mapped value for “Algorithm rsaEncryption; Key size: 2048; Exponent: 0x010001”, which should be the only item in the Original Algorithm column.

Save the database then execute the steps in section 2.1.2.2. Note, key generation for RSA 4096 bit keys is extremely slow. 

**STOPPED HERE** - pg. 8 of MS Word file.
-------------
