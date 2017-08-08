
# GSA's SCVP testing program (GSTP)

GSA's SCVP testing program (GSTP) provides artifacts and tools that may be useful in testing SCVP responders or other products that validate X.509 certificates. The primary components of GSTP are three sets of test artifacts and a test SCVP client. The artifact sets are updates to NIST's PKI Test Suite (PKITS) and Path Discovery Test Suite (PDTS) and a clone of the Federal PKI, called the Mock Federal PKI (MF PKI). Various utilities are provided including a test SCVP client and tools that were used to generate the artifacts or to simplify generation of scripts to drive the test client. Two virtual machines are provided to facilitate testing: an artifacts VM and a tools VM. 

The artifacts VM features an HTTP server that hosts the various artifacts required to conduct the testing, including certificate, PKCS7 and CRL files and OpenSSL-based OCSP responders. The tools VM features the SCVP test client, the PKI Copy and Paste (PCP) utility, the PKI Interoperability Test Tool v2 (PITTv2) utility and other scripts and utilities of more limited value. PCP can be used to refresh artifacts or to add additional test artifacts from the Federal PKI. PITTv2 can be used for testing certification path validation.  

## Getting Started

The easiest way to get started is to download and run the two virtual machines. A hosts file is available from the artifacts VM to enable dynamic discovery of artifacts hosted on the VM. The tools VM will need a copy of this hosts file to facilitate use of PITTv2. The SCVP responder will also require a copy of the hosts file, in order to dynamically build and validate certification paths.

Use PITTv2 to confirm the artifacts VM is functioning properly then configure the test SCVP client for use (i.e., set the host name and key alias in the vss.properties file and add the signing key to the trust store). Use the provided scripts to drive the client or use the SCVP script generator utility to generate new scripts.

### Documentation

Usage guides are available in the docs folders of this repository. The easiest way to get started after configuring the artifacts VM is to download the tools VM, which contains a variety of materials in the home directory of the default pcpadmin user. To configure the SCVP client to reference your responder, add the signing key of the responder to the key store located at `~/scvp-client/vssTrustStore.jks`. Next, edit the `~/scvp-client/vss.properties` file to identify the alias of the key just added to the key store as well as the URL of the SCVP interface in the `VSS_TRUSTSTORE_SCVP_SIGNER_ISSUER_LABEL` and `VSS_SCVP_SERVER_URI` fields.

A full set of scripts are provided in `~/scvp-client/pre-generated-scripts` folder. To run these, use the `GSTPScriptRunner` utility as follows:

```
$ source ~/scvp-client/venv-scvp-client/bin/activate
$ python GSTPScriptRunner.py -i /home/pcpadmin/scvp-client/pregenerated-scripts -l ${SCVP_OUTPUT_PATH} -p HID -d /home/pcpadmin/Desktop/ResponderLogs
```

This command assumes you have created a folder on the desktop to receive sorted copies of logs and have created a folder to receive working logs and saved that to the `SCVP_OUTPUT_PATH` environment variable. 

If you would like to use the provided `PITTv2` utility to test your artifacts VM, update the `/etc/hosts` file to reference your VM.

### Artifacts

PKITS was released by NIST over 15 years ago (then updated this decade to increase RSA key sizes and extend validity dates). None of the certificates included in PKITS feature AIA or CRL DP extensions. GSTP features an updated set of artifacts named PKITSv2 that include AIA and CRL DP extensions. This enables testing without manually provisioning artifacts to each validation engine under test. In addition to adding extensions, PKITSv2 adds editions that feature different public key algorithms and sizes.

Similar to PKITS, PDTS was released by NIST. Unlike PKITS, PDTS has not been maintained and all artifacts in the original test suite have expired. PDTSv2 is a simple update to PDTS that increases the RSA key size, extends the validity dates and drops LDAP tests.

The MF PKI is a new test suite, released for the first time as part of GSTP. The MF PKI was generated using PCP. A set of certificates from the Federal PKI were imported into PCP, additional certificates were harvested automatically by the tool then cloned equivalents were generated. The clones enable testing certification paths that accurately model the Federal PKI with private keys in hand for use in generating digital signatures, authenticating to servers, etc.


### Installing

If using the provided VMs, there is nothing to install. Simply download the VMs, configure the hosts files and use. The test SCVP client and assorted Python scripts can be used in other environments. A CMake configuration file is provided to enable building the SCVP Script Generator utility on other platforms.

## Running the tests

The provided documentation describes how to run the tests. The GSTP Script Runner script is recommended. It facilitates running scripts in batchs with logs saved to folders named with each script's name, a reference to the product being tested and the time the script was executed. The output save to each folder will include a set of summary results, debugging information and scripts to simplify retesting scenarios that failed initially.

