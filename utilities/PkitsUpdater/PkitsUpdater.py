__author__ = 'cwallace'

import glob2
from optparse import OptionParser
import os
from subprocess import PIPE, Popen

# *********************************************************************************************************************
# Four external tools are used.
# *********************************************************************************************************************
# openssl is used to extract private keys from PKCS 12 files (for certificate signing), to convert the extracted private
# key to the format required by ResignCert and to package a PKCS7 with a target certificate.
OPENSSL_EXE = "/usr/bin/openssl"

# FetchKeyId is used to extract SKID values from certificates (during a first pass that builds a map of KIDS to files)
# and AKID values (during a second pass during which certificates are modified and resigned).
FETCH_KID_EXE = "/Users/cwallace/devel/Protiviti/PkitsUpdater/FetchKeyId"

# AddAiaAndCrlDp takes a file to modify, an AIA and a CRL DP and emits a modified version of the certificate containing
# the AIA and CRL DP. The modified certificate will have an invalid signature and must be resigned.
AAACD_EXE = "/Users/cwallace/devel/Protiviti/PkitsUpdater/AddAiaAndCrlDp"

# The ResignCert utility is used to resign certificate after AIA and CRL DP extensions have been added.
RC_EXE = "/Users/cwallace/devel/Protiviti/PkitsUpdater/ResignCert"

RR_EXE = "/Users/cwallace/devel/Protiviti/PkitsUpdater/ResignCrl"


# Some certificates will not be processed. These include all DSA certificates and the root itself, which requires
# neither an AIA nor CRL DP extension.
skip_certs = [
    "DSACACert.crt",
    "DSAParametersInheritedCACert.crt",
    "InvalidDSASignatureTest6EE.crt",
    "ValidDSAParameterInheritanceTest5EE.crt",
    "ValidDSASignaturesTest4EE.crt",
    "TrustAnchorRootCertificate.crt"
]

broken_signatures = [
    'BadSignedCACert.crt',
    'InvalidEESignatureTest3EE.crt'
]

needs_two = {
    'BasicSelfIssuedCRLSigningKeyCACert.crt': 'BasicSelfIssuedCRLSigningKeyCRLCert.crt',
    'BasicSelfIssuedOldKeyNewWithOldCACert.crt': 'BasicSelfIssuedOldKeyCACert.crt',
    'BasicSelfIssuedNewKeyCACert.crt': 'BasicSelfIssuedNewKeyOldWithNewCACert.crt',
    'indirectCRLCA2Cert.crt': 'indirectCRLCA1Cert.crt',
    'indirectCRLCA3Cert.crt': 'indirectCRLCA3cRLIssuerCert.crt',
    'indirectCRLCA4Cert.crt': 'indirectCRLCA4cRLIssuerCert.crt',
    'indirectCRLCA6Cert.crt': 'indirectCRLCA5Cert.crt',
    'SeparateCertificateandCRLKeysCertificateSigningCACert.crt': 'SeparateCertificateandCRLKeysCRLSigningCert.crt',
    'SeparateCertificateandCRLKeysCA2CRLSigningCert.crt': 'SeparateCertificateandCRLKeysCA2CertificateSigningCACert.crt',

}

alt_crl_file = {
    'nameConstraintsDN1SelfIssuedCACert.crl': 'nameConstraintsDN1CACert.crl',
    'inhibitAnyPolicy1SelfIssuedCACRL.crl': 'inhibitAnyPolicy1CACRL.crl',
    'inhibitPolicyMapping1P1SelfIssuedCACRL.crl': 'inhibitPolicyMapping1P1CACRL.crl',
    'pathLenConstraint0SelfIssuedCACRL.crl': 'pathLenConstraint0CACRL.crl',
    'pathLenConstraint1SelfIssuedsubCACRL.crl': 'pathLenConstraint1subCACRL.crl',
    'requireExplicitPolicy2SelfIssuedCACRL.crl': 'requireExplicitPolicy2CACRL.crl',
    'BasicSelfIssuedOldKeyNewWithOldCACRL.crl': 'BasicSelfIssuedOldKeySelfIssuedCertCRL.crl',
    'indirectCRLCA4CRL.crl': 'indirectCRLCA4cRLIssuerCRL.crl',
    'indirectCRLCA6CRL.crl': 'indirectCRLCA5CRL.crl',
    'indirectCRLCA2CRL.crl': 'indirectCRLCA1CRL.crl',
    'SeparateCertificateandCRLKeysCertificateSigningCACRL.crl':'SeparateCertificateandCRLKeysCRL.crl',
    'SeparateCertificateandCRLKeysCA2CertificateSigningCACRL.crl':'SeparateCertificateandCRLKeysCRL2.crl',
    'SeparateCertificateandCRLKeysCRLSigningCRL.crl': 'SeparateCertificateandCRLKeysCRL.crl'
}

delta_tests = [
    'InvaliddeltaCRLIndicatorNoBaseTest1EE.crt',
    'InvaliddeltaCRLTest10EE.crt',
    'InvaliddeltaCRLTest3EE.crt',
    'InvaliddeltaCRLTest4EE.crt',
    'InvaliddeltaCRLTest6EE.crt',
    'InvaliddeltaCRLTest9EE.crt',
    'ValiddeltaCRLTest2EE.crt',
    'ValiddeltaCRLTest5EE.crt',
    'ValiddeltaCRLTest8EE.crt',
    'ValiddeltaCRLTest7EE.crt'
]

indirect_crls = [
    "indirectCRLCA1CRL.crl",
    "indirectCRLCA3CRL.crl",
    "indirectCRLCA3cRLIssuerCRL.crl",
    "indirectCRLCA4cRLIssuerCRL.crl",
    "indirectCRLCA5CRL.crl"
]

other_crls_that_need_aias = [
    "SeparateCertificateandCRLKeysCRL.crl",
    "BasicSelfIssuedCRLSigningKeyCACRL.crl"
]

alt_indirect = {
    'indirectCRLCA2Cert.crt': 'indirectCRLCA1Cert.crt',
    'indirectCRLCA3Cert.crt': 'indirectCRLCA3cRLIssuerCert.crt',
    'indirectCRLCA4Cert.crt': 'indirectCRLCA4cRLIssuerCert.crt',
    'indirectCRLCA6Cert.crt': 'indirectCRLCA5Cert.crt'
}

alt_p7 = {
    'SeparateCertificateandCRLKeysCRLSigningCert.p7b' : 'SeparateCertificateandCRLKeysCertificateSigningCACert.p7b'
}

two_crls = ['ValidTwoCRLsTest7EE.crt']
some_reasons1 = ['ValidonlySomeReasonsTest18EE.crt']
some_reasons2 = ['ValidonlySomeReasonsTest18EE.crt', 'ValidonlySomeReasonsTest19EE.crt']
outlier1 = ['BasicSelfIssuedCRLSigningKeyCRLCert.crt']
# outlier2 = ['BasicSelfIssuedNewKeyOldWithNewCACert.crt', 'ValidBasicSelfIssuedNewWithOldTest4EE.crt']
outlier2 = ['ValidBasicSelfIssuedNewWithOldTest4EE.crt']
outlier3 = [] # ['ValidBasicSelfIssuedOldWithNewTest1EE.crt']
outlier4 = ['ValidcRLIssuerTest28EE.crt', 'ValidcRLIssuerTest29EE.crt']
outlier5 = ['BasicSelfIssuedNewKeyOldWithNewCACert.crt', 'ValidBasicSelfIssuedOldWithNewTest1EE.crt']
outlier6 = ['BasicSelfIssuedOldKeyNewWithOldCACert.crt']
outlier7 = ['ValidBasicSelfIssuedNewWithOldTest3EE.crt']


p7_outlier1 = ['ValidBasicSelfIssuedOldWithNewTest1EE.crt']

def main():
    parser = OptionParser()
    parser.add_option("-p", "--pkitsFolder", dest="pkits_folder", default="",
                      help="Folder containing certpairs, certs, crls, pkcs12 and smime folders (and to receive pkcs7 and new_certs folders)")

    (options, args) = parser.parse_args()

    if not options.pkits_folder:
        print("You must specify a PKITS folder to process")
    else:
        # create the folders to receive PKCS7 objects and modified certificates.

        new_certs_folder = options.pkits_folder + "/new_certs/"

        try:
            os.stat(new_certs_folder)
        except:
            os.mkdir(new_certs_folder)

        new_crls_folder = options.pkits_folder + "/new_crls/"

        try:
            os.stat(new_crls_folder)
        except:
            os.mkdir(new_crls_folder)

        p7s_folder = options.pkits_folder + "/pkcs7/"

        try:
            os.stat(p7s_folder)
        except:
            os.mkdir(p7s_folder)

        p12_folder = options.pkits_folder + "/pkcs12/"

        # get a list of all of the original file names
        orig_cert_files = glob2.glob(options.pkits_folder + '/certs/*.crt')
        orig_crl_folder = options.pkits_folder + "/crls/"

        # build a map of filenames mapping subject key identifier to filename
        orig_dict = {}
        for filename in orig_cert_files:
            fetch_kid_command = FETCH_KID_EXE + " -c " + filename
            p = Popen(fetch_kid_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            skid = line.decode("utf-8").strip()
            orig_dict[skid] = filename

        issuer_files = []

        # declare base URLs for each extension. File names will be appended. Hosts files can be used to adjust IP
        # addresses to point to hosting location.
        aiabaseUrl = "http://betty.pkits.test/aia/"
        crlbaseUrl = "http://betty.pkits.test/crl/"

        for crl in indirect_crls:
            print("Processing " + filename)

            # get the AKID value
            fetch_kid_command = FETCH_KID_EXE + " -a -r " + orig_crl_folder + crl
            p = Popen(fetch_kid_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            akid = line.decode("utf-8").strip()
            if not akid:
                print("Error processing " + orig_crl_folder + crl)
                continue

            # look up the issuer's filename in the map created above
            issuer_filename = orig_dict[akid]
            if not issuer_filename:
                print("ERROR: failed to lookup issuer using AKID value when processing " + filename)
                continue

            # get the filename
            fn = os.path.basename(issuer_filename)

            # remove the extension (since we will need to generate or reference a few different extensions
            no_ext = os.path.splitext(fn)[0]

            # prepare the p12_filename for the issuer
            p12_filename = p12_folder + os.path.splitext(fn)[0]+'.p12'
            if not os.path.isfile(p12_filename):
                print("ERROR: failed to find issuer's PKCS 12 when processing " + filename)
                continue

            p7_filename = no_ext +'.p7b'
            crl_filename = no_ext + '.crl'
            pem_cert_filename = p12_folder + no_ext + '.crt.pem'

            if fn == "TrustAnchorRootCertificate.crt":
                crl_filename = "TrustAnchorRootCRL.crl"
            else:
                crl_filename = crl_filename.replace("Cert.", "CRL.")

            if crl_filename in alt_crl_file.keys():
                crl_filename = alt_crl_file[crl_filename]

            pem_filename = p12_folder + no_ext + '.pem'
            p8_filename = p12_folder + no_ext + '.p8'

            # if fn in alt_indirect.keys():
            #     alt_issuer = alt_indirect[fn]
            #     alt_no_ext = os.path.splitext(alt_issuer)[0]
            #     p7_filename = alt_no_ext + '.p7b'

            aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -r " + orig_crl_folder + crl + " --mod_crl " + orig_crl_folder + crl + ".tmp"
            p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
            p.wait()

            openssl_command = OPENSSL_EXE + " pkcs12 -passin pass:password -in " + p12_filename + " -nodes -out " + pem_filename
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            openssl_command = OPENSSL_EXE + " pkcs8 -topk8 -inform PEM -outform DER -in " + pem_filename + " -out " + p8_filename + " -nocrypt"
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            rr_command = RR_EXE + " -p " + p8_filename + " -i " + orig_crl_folder + crl + ".tmp" + " -o " + new_crls_folder + crl
            p = Popen(rr_command, shell=True, stdout=PIPE)
            p.wait()

            # if issuer_filename in alt_indirect.keys():
            # alt_issuer = alt_indirect[issuer_filename]
            # alt_no_ext = os.path.splitext(alt_issuer)[0]
            # p7_filename = alt_no_ext + '.p7b'

            openssl_command = OPENSSL_EXE + " x509 -inform DER -outform PEM -in " + new_certs_folder + fn + " -out " + pem_cert_filename
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            openssl_command = OPENSSL_EXE + " crl2pkcs7 -nocrl -outform DER -certfile " + pem_cert_filename + " -out " + p7s_folder + p7_filename
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

        for crl in other_crls_that_need_aias:
            print("Processing " + filename)

            # get the AKID value
            fetch_kid_command = FETCH_KID_EXE + " -a -r " + orig_crl_folder + crl
            p = Popen(fetch_kid_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            akid = line.decode("utf-8").strip()
            if not akid:
                print("Error processing " + orig_crl_folder + crl)
                continue

            # look up the issuer's filename in the map created above
            issuer_filename = orig_dict[akid]
            if not issuer_filename:
                print("ERROR: failed to lookup issuer using AKID value when processing " + filename)
                continue

            # get the filename
            fn = os.path.basename(issuer_filename)

            # remove the extension (since we will need to generate or reference a few different extensions
            no_ext = os.path.splitext(fn)[0]

            # prepare the p12_filename for the issuer
            p12_filename = p12_folder + os.path.splitext(fn)[0]+'.p12'
            if not os.path.isfile(p12_filename):
                print("ERROR: failed to find issuer's PKCS 12 when processing " + filename)
                continue

            p7_filename = no_ext +'.p7b'
            crl_filename = no_ext + '.crl'
            pem_cert_filename = p12_folder + no_ext + '.crt.pem'

            if fn == "TrustAnchorRootCertificate.crt":
                crl_filename = "TrustAnchorRootCRL.crl"
            else:
                crl_filename = crl_filename.replace("Cert.", "CRL.")

            if crl_filename in alt_crl_file.keys():
                crl_filename = alt_crl_file[crl_filename]

            if p7_filename in alt_p7.keys():
                p7_filename = alt_p7[p7_filename]

            pem_filename = p12_folder + no_ext + '.pem'
            p8_filename = p12_folder + no_ext + '.p8'

            # if fn in alt_indirect.keys():
            #     alt_issuer = alt_indirect[fn]
            #     alt_no_ext = os.path.splitext(alt_issuer)[0]
            #     p7_filename = alt_no_ext + '.p7b'

            aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -r " + orig_crl_folder + crl + " --mod_crl " + orig_crl_folder + crl + ".tmp"
            p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
            p.wait()

            openssl_command = OPENSSL_EXE + " pkcs12 -passin pass:password -in " + p12_filename + " -nodes -out " + pem_filename
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            openssl_command = OPENSSL_EXE + " pkcs8 -topk8 -inform PEM -outform DER -in " + pem_filename + " -out " + p8_filename + " -nocrypt"
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            rr_command = RR_EXE + " -p " + p8_filename + " -i " + orig_crl_folder + crl + ".tmp" + " -o " + new_crls_folder + crl
            p = Popen(rr_command, shell=True, stdout=PIPE)
            p.wait()

            # if issuer_filename in alt_indirect.keys():
            # alt_issuer = alt_indirect[issuer_filename]
            # alt_no_ext = os.path.splitext(alt_issuer)[0]
            # p7_filename = alt_no_ext + '.p7b'

            openssl_command = OPENSSL_EXE + " x509 -inform DER -outform PEM -in " + new_certs_folder + fn + " -out " + pem_cert_filename
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            openssl_command = OPENSSL_EXE + " crl2pkcs7 -nocrl -outform DER -certfile " + pem_cert_filename + " -out " + p7s_folder + p7_filename
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

        for filename in orig_cert_files:
            # check the list of certificates to skip
            if os.path.basename(filename) in skip_certs:
                print("Skipping " + filename)
                continue

            print("Processing " + filename)

            # get the AKID value
            fetch_kid_command = FETCH_KID_EXE + " -a -c " + filename
            p = Popen(fetch_kid_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            akid = line.decode("utf-8").strip()

            # look up the issuer's filename in the map created above
            issuer_filename = orig_dict[akid]
            if not issuer_filename:
                print("ERROR: failed to lookup issuer using AKID value when processing " + filename)
                continue

            # get the filename
            fn = os.path.basename(issuer_filename)

            # remove the extension (since we will need to generate or reference a few different extensions
            no_ext = os.path.splitext(fn)[0]

            # prepare the p12_filename for the issuer
            p12_filename = p12_folder + os.path.splitext(fn)[0]+'.p12'
            if not os.path.isfile(p12_filename):
                print("ERROR: failed to find issuer's PKCS 12 when processing " + filename)
                continue

            p7_filename = no_ext +'.p7b'
            crl_filename = no_ext + '.crl'
            pem_cert_filename = p12_folder + no_ext + '.crt.pem'

            if fn == "TrustAnchorRootCertificate.crt":
                crl_filename = "TrustAnchorRootCRL.crl"
            else:
                crl_filename = crl_filename.replace("Cert.", "CRL.")

            if crl_filename in alt_crl_file.keys():
                crl_filename = alt_crl_file[crl_filename]

            pem_filename = p12_folder + no_ext + '.pem'
            p8_filename = p12_folder + no_ext + '.p8'

            # subject-related files
            subject_filename = os.path.basename(filename)
            new_cert = new_certs_folder + subject_filename
            tmp_filename = filename + ".tmp"

            if os.path.basename(filename) in delta_tests:
                delta_crl_filename = crl_filename.replace('CRL.crl', 'deltaCRL.crl')
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + crl_filename + " --freshest " + crlbaseUrl + delta_crl_filename + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in two_crls:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'TwoCRLsCAGoodCRL.crl' + " --crldp_first " + crlbaseUrl + 'TwoCRLsCABadCRL.crl' + " -i " + filename  + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in some_reasons1:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'onlySomeReasonsCA3compromiseCRL.crl' + " --crldp_first " + crlbaseUrl + 'onlySomeReasonsCA3otherreasonsCRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in some_reasons2:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'onlySomeReasonsCA4compromiseCRL.crl' + " --crldp_first " + crlbaseUrl + 'onlySomeReasonsCA4otherreasonsCRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in outlier1:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'BasicSelfIssuedCRLSigningKeyCRLCertCRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in outlier2:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'BasicSelfIssuedOldKeyCACRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in outlier3:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'BasicSelfIssuedNewKeyCACRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in outlier4:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'indirectCRLCA3cRLIssuerCRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in outlier5:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'BasicSelfIssuedNewKeyCACRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in outlier6:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'BasicSelfIssuedOldKeySelfIssuedCertCRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            elif os.path.basename(filename) in outlier7:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + 'BasicSelfIssuedOldKeyCACRL.crl' + " -i " + filename + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()
            else:
                aaacd_kid_command = AAACD_EXE + " -a " + aiabaseUrl + p7_filename + " -c " + crlbaseUrl + crl_filename + " -i " + filename  + " -o " + tmp_filename
                p = Popen(aaacd_kid_command, shell=True, stdout=PIPE)
                p.wait()

            openssl_command = OPENSSL_EXE + " pkcs12 -passin pass:password -in " + p12_filename + " -nodes -out " + pem_filename
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            openssl_command = OPENSSL_EXE + " pkcs8 -topk8 -inform PEM -outform DER -in " + pem_filename + " -out " + p8_filename + " -nocrypt"
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            p.wait()

            if fn not in issuer_files:
                issuer_files.append(fn)

            rc_command = RC_EXE + " -p " + p8_filename + " -i " + tmp_filename + " -o " + new_cert
            p = Popen(rc_command, shell=True, stdout=PIPE)
            p.wait()

            if os.path.basename(filename) in broken_signatures:
                with open(new_cert, mode='rb') as file:
                    fileContent = bytearray(file.read())
                    num_bytes = len(fileContent)
                    if fileContent[num_bytes-1] == 0xFF:
                        fileContent[num_bytes-1] = 0xFE
                    else:
                        fileContent[num_bytes-1] = 0xFF
                    file.close()
                    fw = open(new_cert, mode='wb')
                    fw.write(fileContent)
                    fw.close()

            if os.path.isfile(new_cert):
                print("Successfully processed " + filename)
            else:
                print("ERROR: Failed to process " + filename)

            if os.path.isfile(pem_filename):
                os.remove(pem_filename)
            if os.path.isfile(p8_filename):
                os.remove(p8_filename)
            if os.path.isfile(tmp_filename):
                os.remove(tmp_filename)

        for issuer_filename in issuer_files:
            # check the list of certificates to skip
            if os.path.basename(issuer_filename) in skip_certs:
                print("Skipping " + issuer_filename + " during P7 preparation")
                continue

            # get the filename
            fn = os.path.basename(issuer_filename)

            # remove the extension (since we will need to generate or reference a few different extensions
            no_ext = os.path.splitext(fn)[0]
            p7_filename = no_ext + '.p7b'

            new_cert = new_certs_folder + issuer_filename
            pem_cert_filename = new_cert + ".pem"

            if fn in needs_two.keys():
                second = needs_two[fn]
                # get the filename
                second_fn = os.path.basename(second)

                # remove the extension (since we will need to generate or reference a few different extensions
                second_no_ext = os.path.splitext(second_fn)[0]
                second_p7_filename = no_ext + '.p7b'

                second_new_cert = new_certs_folder + second_fn
                second_pem_cert_filename = second_new_cert + ".pem"

                openssl_command = OPENSSL_EXE + " x509 -inform DER -outform PEM -in " + new_cert + " -out " + pem_cert_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()

                openssl_command = OPENSSL_EXE + " x509 -inform DER -outform PEM -in " + second_new_cert + " -out " + second_pem_cert_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()

                openssl_command = OPENSSL_EXE + " crl2pkcs7 -nocrl -outform DER -certfile " + pem_cert_filename + " -certfile " + second_pem_cert_filename + " -out " + p7s_folder + p7_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()
            elif fn in p7_outlier1:
                openssl_command = OPENSSL_EXE + " x509 -inform DER -outform PEM -in " + new_certs_folder + 'BasicSelfIssuedNewKeyCACert.crt' + " -out " + pem_cert_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()

                openssl_command = OPENSSL_EXE + " crl2pkcs7 -nocrl -outform DER -certfile " + pem_cert_filename + " -out " + p7s_folder + p7_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()
            else:
                openssl_command = OPENSSL_EXE + " x509 -inform DER -outform PEM -in " + new_cert + " -out " + pem_cert_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()

                openssl_command = OPENSSL_EXE + " crl2pkcs7 -nocrl -outform DER -certfile " + pem_cert_filename + " -out " + p7s_folder + p7_filename
                p = Popen(openssl_command, shell=True, stdout=PIPE)
                p.wait()

            os.remove(pem_cert_filename)


if __name__ == '__main__':
    main()