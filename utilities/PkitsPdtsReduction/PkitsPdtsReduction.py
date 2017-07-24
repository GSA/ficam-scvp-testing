__author__ = 'cwallace'

import glob2
from optparse import OptionParser
import os
from subprocess import PIPE, Popen, call
from shutil import copyfile

OPENSSL_EXE = "/usr/bin/openssl"

pkits_files_to_omit = [
    "DSACACert.crt",
    "DSAParametersInheritedCACert.crt",
    "InvalidDSASignatureTest6EE.crt",
    "ValidDSAParameterInheritanceTest5EE.crt",
    "ValidDSASignaturesTest4EE.crt",
    "DSACACRL.crl",
    "DSAParametersInheritedCACRL.crl"
]

pdts_files_to_keep = [
    "BasicHTTPURIPathDiscoveryOU1EE1.crt",
    "BasicHTTPURIPathDiscoveryOU1EE2.crt",
    "BasicHTTPURIPathDiscoveryOU1EE3.crt",
    "BasicHTTPURIPathDiscoveryOU1EE4.crt",
    "BasicHTTPURIPathDiscoveryOU1EE5.crt",
    "BasicHTTPURIPathDiscoveryOU3EE1.crt",
    "BasicHTTPURIPathDiscoveryOU3EE2.crt",
    "BasicHTTPURIPathDiscoveryOrg2EE1.crt",
    "BasicHTTPURIPathDiscoveryOrg2EE2.crt",
    "BasicHTTPURIPathDiscoveryOrg2EE3.crt",
    "BasicHTTPURIPathDiscoveryOrg2EE4.crt",
    "BasicHTTPURIPathDiscoveryOrg2EE5.crt",
    "BasicHTTPURIPathDiscoveryTest2EE.crt",
    "BasicHTTPURIPathDiscoveryTest4EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest13EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest14EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest15EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest16EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest2EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest4EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest7EE.crt",
    "RudimentaryHTTPURIPathDiscoveryTest8EE.crt",
    "BasicHTTPURITrustAnchorRootCert.crt"
]

def main():
    parser = OptionParser()
    parser.add_option("-v", "--pkits", dest="pkits_folder", default="",
                      help="Root of PKITS folder (containing certs, certpairs, crls, pkcs12 and smime")
    parser.add_option("-d", "--pdts", dest="pdts_folder", default="",
                      help="Root of PDTS folder (containing Trust Anchor Certs, smime, pkcs12 and End Entity Certs")

    (options, args) = parser.parse_args()

    if options.pkits_folder:
        certs_folder = os.path.join(options.pkits_folder, "certs")
        orig_cert_files = glob2.glob(certs_folder + '/*.crt')
        crls_folder = os.path.join(options.pkits_folder, "crls")
        orig_crl_files = glob2.glob(crls_folder + '/*.crl')

        for filename in orig_cert_files:
            orig_name = os.path.basename(filename)

            if orig_name in pkits_files_to_omit:
                os.rename(filename, filename + ".omit")
                print("Renaming " + filename + " to " + filename + ".omit")

        for filename in orig_crl_files:
            orig_name = os.path.basename(filename)

            if orig_name in pkits_files_to_omit:
                os.rename(filename, filename + ".omit")
                print("Renaming " + filename + " to " + filename + ".omit")

    if options.pdts_folder:
        certs_folder = os.path.join(options.pdts_folder, "End Entity Certs")
        orig_cert_files = glob2.glob(certs_folder + '/*.crt')
        tas_folder = os.path.join(options.pdts_folder, "Trust Anchor Certs")
        orig_ta_files = glob2.glob(tas_folder + '/*.crl')

        for filename in orig_cert_files:
            orig_name = os.path.basename(filename)

            if orig_name not in pdts_files_to_keep:
                os.rename(filename, filename + ".omit")
                print("Renaming " + filename + " to " + filename + ".omit")

        for filename in orig_ta_files:
            orig_name = os.path.basename(filename)

            if orig_name not in pdts_files_to_keep:
                os.rename(filename, filename + ".omit")
                print("Renaming " + filename + " to " + filename + ".omit")

if __name__ == '__main__':
    main()