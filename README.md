This repository was archived on July 14, 2021 and will no longer be maintained. The SCVP testing category was [deprecated on April 30, 2019](https://ww.idmanagement.gov/sell/fipsannouncements/#category-removed-from-the-apl-april-2019). 

GSA's FIPS 201 Evaluation Program: Server-Based Certificate Validation Protocol (SCVP) Responder Testing
========================================================================================================

- [Introduction](#introduction) 
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Testing Components](#testing-components)
- [License](#license)
- [Contact Information](#contact-information)


Introduction
------------

GSA's FIPS 201 Evaluation Program is responsible for evaluating and approving products required for the implementation of HSPD-12 ([see OMB M-06-18)](https://www.whitehouse.gov/sites/whitehouse.gov/files/omb/memoranda/2006/m06-18.pdf).
- This repository holds open-source testing tools to test [Server-Based Certificate Validation Protocol (SCVP)](https://tools.ietf.org/html/rfc5055) responders conformance to the [Treasury SCVP Request and Response Profile](https://vssapi-dev.treasury.gov/vss/docs/treas_scvp_profile_v1.3.pdf). 
- SCVP responders that successfully pass testing will be listed on the [FIPS 201 - Approved Products List](https://www.idmanagement.gov/approved-products-list/)


Quick Start
-----------

If using the provided VMs, there is nothing to install. Simply download the VMs, configure the host files and use.
- [el7-artifacthost.ova](https://github.com/GSA/ficam-scvp-testing)
- [el7-tools.ova](https://github.com/GSA/ficam-scvp-testing)


Documentation
-------------

The user guide below describes how to use the SCVP test client. 
- [SCVP Test Client User Guide](https://github.com/GSA/ficam-scvp-testing/blob/master/docs/scvp_test_prog_user_guide.md)

If you need to re-generate any testing artifacts, you can use this guide for detailed steps on updating any of the testing artifacts. Note, this guide is only necessary if you need to change something. Artifacts are available by default on the el7-artifacthost.ova virtual machine.
- [Re-generate Test Artifacts](https://github.com/GSA/ficam-scvp-testing/blob/master/docs/scvp_test_prog_artifacts.md)


Testing Components
------------------
The primary components used for testing the SCVP responders consist of three sets of test artifacts and a test SCVP client.

#### The Artifacts
The artifact sets are updates to [NIST's PKI Test Suite (PKITS) and Path Discovery Test Suite (PDTS)](https://csrc.nist.gov/Projects/PKI-Testing) and a clone of the Federal PKI, called the Mock Federal PKI (MF PKI).

#### Public Key Infrastructure Test Suite (PKITS)
PKITS was released by NIST over 15 years ago (then updated this decade to increase RSA key sizes and extend validity dates).
- None of the certificates included in PKITS feature AIA or CRL DP extensions.
- We've updated the artifacts to include AIA and CRL DP extensions; renamed them to PKITSv2.
- This enables testing without manually provisioning artifacts to each validation engine under test.
- In addition to adding extensions, PKITSv2 adds editions that feature different public key algorithms and sizes.

#### Path Discovery Test Suite (PDTS)
Similar to PKITS, PDTS was released by NIST. Unlike PKITS, PDTS has not been maintained and all artifacts in the original test suite have expired.
- PDTSv2 is a simple update to PDTS that increases the RSA key size, extends the validity dates and drops LDAP tests.

#### Mock Federal PKI (MF PKI)
The MF PKI is a new test suite, released for the first time as part of this work.
- The MF PKI was generated using PCP.
- A set of certificates from the Federal PKI were imported into PCP, additional certificates were harvested automatically by the tool then cloned equivalents were generated.
- The clones enable testing certification paths that accurately model the Federal PKI with private keys in hand for use in generating digital signatures, authenticating to servers, etc.

License
-------

This project is in the public domain within the United States.

We waive copyright and related rights in the work worldwide through the CC0 1.0 Universal public domain dedication.

Please review the License found in this repository.

Contact Information
-------------------
For issues, please open an Issue in this repository. Contact icam at gsa.gov for any additional questions on contributing.
