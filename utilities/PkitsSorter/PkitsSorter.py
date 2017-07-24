__author__ = 'cwallace'

import glob2
from optparse import OptionParser
import os
from subprocess import PIPE, Popen, call
from shutil import copyfile

OPENSSL_EXE = "/usr/bin/openssl"

sorted_pkits = {}

sorted_pkits["1"] = [
    "AllCertificatesNoPoliciesTest2EE.crt",
    "CPSPointerQualifierTest20EE.crt",
    "DifferentPoliciesTest3EE.crt",
    "ValidCertificatePathTest1EE.crt",
]
sorted_pkits["10"] = [
    "inhibitAnyPolicyTest3EE.crt",
]
sorted_pkits["2"] = [
    "ValidCertificatePathTest1EE.crt",
]
sorted_pkits["3"] = [
    "ValidCertificatePathTest1EE.crt"
]
sorted_pkits["4"] = [
    "DifferentPoliciesTest3EE.crt",
    "ValidCertificatePathTest1EE.crt"
]
sorted_pkits["5"] = [
    "AllCertificatesSamePoliciesTest10EE.crt",
    "AllCertificatesSamePoliciesTest13EE.crt",
    "AllCertificatesanyPolicyTest11EE.crt",
    "AnyPolicyTest14EE.crt",
    "InvalidPolicyMappingTest4EE.crt",
    "OverlappingPoliciesTest6EE.crt",
    "UserNoticeQualifierTest18EE.crt",
    "ValidPolicyMappingTest12EE.crt",
    "ValidPolicyMappingTest1EE.crt",
    "ValidPolicyMappingTest3EE.crt",
    "ValidPolicyMappingTest5EE.crt",
    "ValidPolicyMappingTest6EE.crt"
]
sorted_pkits["6"] = [
    "AllCertificatesSamePoliciesTest10EE.crt",
    "AllCertificatesSamePoliciesTest13EE.crt",
    "AnyPolicyTest14EE.crt",
    "OverlappingPoliciesTest6EE.crt",
    "UserNoticeQualifierTest18EE.crt",
    "ValidPolicyMappingTest12EE.crt",
    "ValidPolicyMappingTest1EE.crt",
    "ValidPolicyMappingTest3EE.crt"
]
sorted_pkits["7"] = [
    "AllCertificatesSamePoliciesTest13EE.crt"
]
sorted_pkits["8"] = [
    "InvalidPolicyMappingTest2EE.crt",
    "ValidPolicyMappingTest1EE.crt"
]
sorted_pkits["9"] = [
    "ValidPolicyMappingTest5EE.crt",
    "ValidPolicyMappingTest6EE.crt"
]

sorted_pkits["default"] = [
    "AllCertificatesNoPoliciesTest2EE.crt",
    "AllCertificatesSamePoliciesTest10EE.crt",
    "AllCertificatesanyPolicyTest11EE.crt",
    "CPSPointerQualifierTest20EE.crt",
    "DifferentPoliciesTest12EE.crt",
    "DifferentPoliciesTest3EE.crt",
    "DifferentPoliciesTest4EE.crt",
    "DifferentPoliciesTest5EE.crt",
    "DifferentPoliciesTest7EE.crt",
    "DifferentPoliciesTest8EE.crt",
    "DifferentPoliciesTest9EE.crt",
    "InvalidBadCRLIssuerNameTest5EE.crt",
    "InvalidBadCRLSignatureTest4EE.crt",
    "InvalidBasicSelfIssuedCRLSigningKeyTest7EE.crt",
    "InvalidBasicSelfIssuedCRLSigningKeyTest8EE.crt",
    "InvalidBasicSelfIssuedNewWithOldTest5EE.crt",
    "InvalidBasicSelfIssuedOldWithNewTest2EE.crt",
    "InvalidCASignatureTest2EE.crt",
    "InvalidCAnotAfterDateTest5EE.crt",
    "InvalidCAnotBeforeDateTest1EE.crt",
    "InvalidDNSnameConstraintsTest31EE.crt",
    "InvalidDNSnameConstraintsTest33EE.crt",
    "InvalidDNSnameConstraintsTest38EE.crt",
    "InvalidDNandRFC822nameConstraintsTest28EE.crt",
    "InvalidDNandRFC822nameConstraintsTest29EE.crt",
    "InvalidDNnameConstraintsTest10EE.crt",
    "InvalidDNnameConstraintsTest12EE.crt",
    "InvalidDNnameConstraintsTest13EE.crt",
    "InvalidDNnameConstraintsTest15EE.crt",
    "InvalidDNnameConstraintsTest16EE.crt",
    "InvalidDNnameConstraintsTest17EE.crt",
    "InvalidDNnameConstraintsTest20EE.crt",
    "InvalidDNnameConstraintsTest2EE.crt",
    "InvalidDNnameConstraintsTest3EE.crt",
    "InvalidDNnameConstraintsTest7EE.crt",
    "InvalidDNnameConstraintsTest8EE.crt",
    "InvalidDNnameConstraintsTest9EE.crt",
    "InvalidDSASignatureTest6EE.crt",
    "InvalidEESignatureTest3EE.crt",
    "InvalidEEnotAfterDateTest6EE.crt",
    "InvalidEEnotBeforeDateTest2EE.crt",
    "InvalidIDPwithindirectCRLTest23EE.crt",
    "InvalidIDPwithindirectCRLTest26EE.crt",
    "InvalidLongSerialNumberTest18EE.crt",
    "InvalidMappingFromanyPolicyTest7EE.crt",
    "InvalidMappingToanyPolicyTest8EE.crt",
    "InvalidMissingCRLTest1EE.crt",
    "InvalidMissingbasicConstraintsTest1EE.crt",
    "InvalidNameChainingTest1EE.crt",
    "InvalidNegativeSerialNumberTest15EE.crt",
    "InvalidOldCRLnextUpdateTest11EE.crt",
    "InvalidPolicyMappingTest10EE.crt",
    "InvalidPolicyMappingTest2EE.crt",
    "InvalidRFC822nameConstraintsTest22EE.crt",
    "InvalidRFC822nameConstraintsTest24EE.crt",
    "InvalidRFC822nameConstraintsTest26EE.crt",
    "InvalidRevokedCATest2EE.crt",
    "InvalidRevokedEETest3EE.crt",
    "InvalidSelfIssuedinhibitAnyPolicyTest10EE.crt",
    "InvalidSelfIssuedinhibitAnyPolicyTest8EE.crt",
    "InvalidSelfIssuedinhibitPolicyMappingTest10EE.crt",
    "InvalidSelfIssuedinhibitPolicyMappingTest11EE.crt",
    "InvalidSelfIssuedinhibitPolicyMappingTest8EE.crt",
    "InvalidSelfIssuedinhibitPolicyMappingTest9EE.crt",
    "InvalidSelfIssuedpathLenConstraintTest16EE.crt",
    "InvalidSelfIssuedrequireExplicitPolicyTest7EE.crt",
    "InvalidSelfIssuedrequireExplicitPolicyTest8EE.crt",
    "InvalidSeparateCertificateandCRLKeysTest20EE.crt",
    "InvalidSeparateCertificateandCRLKeysTest21EE.crt",
    "InvalidURInameConstraintsTest35EE.crt",
    "InvalidURInameConstraintsTest37EE.crt",
    "InvalidUnknownCRLEntryExtensionTest8EE.crt",
    "InvalidUnknownCRLExtensionTest10EE.crt",
    "InvalidUnknownCRLExtensionTest9EE.crt",
    "InvalidUnknownCriticalCertificateExtensionTest2EE.crt",
    "InvalidWrongCRLTest6EE.crt",
    "InvalidcAFalseTest2EE.crt",
    "InvalidcAFalseTest3EE.crt",
    "InvalidcRLIssuerTest27EE.crt",
    "InvalidcRLIssuerTest31EE.crt",
    "InvalidcRLIssuerTest32EE.crt",
    "InvalidcRLIssuerTest34EE.crt",
    "InvalidcRLIssuerTest35EE.crt",
    "InvaliddeltaCRLIndicatorNoBaseTest1EE.crt",
    "InvaliddeltaCRLTest10EE.crt",
    "InvaliddeltaCRLTest3EE.crt",
    "InvaliddeltaCRLTest4EE.crt",
    "InvaliddeltaCRLTest6EE.crt",
    "InvaliddeltaCRLTest9EE.crt",
    "InvaliddistributionPointTest2EE.crt",
    "InvaliddistributionPointTest3EE.crt",
    "InvaliddistributionPointTest6EE.crt",
    "InvaliddistributionPointTest8EE.crt",
    "InvaliddistributionPointTest9EE.crt",
    "InvalidinhibitAnyPolicyTest1EE.crt",
    "InvalidinhibitAnyPolicyTest4EE.crt",
    "InvalidinhibitAnyPolicyTest5EE.crt",
    "InvalidinhibitAnyPolicyTest6EE.crt",
    "InvalidinhibitPolicyMappingTest1EE.crt",
    "InvalidinhibitPolicyMappingTest3EE.crt",
    "InvalidinhibitPolicyMappingTest5EE.crt",
    "InvalidinhibitPolicyMappingTest6EE.crt",
    "InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt",
    "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt",
    "InvalidkeyUsageNotCriticalcRLSignFalseTest5EE.crt",
    "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt",
    "InvalidonlyContainsAttributeCertsTest14EE.crt",
    "InvalidonlyContainsCACertsTest12EE.crt",
    "InvalidonlyContainsUserCertsTest11EE.crt",
    "InvalidonlySomeReasonsTest15EE.crt",
    "InvalidonlySomeReasonsTest16EE.crt",
    "InvalidonlySomeReasonsTest17EE.crt",
    "InvalidonlySomeReasonsTest20EE.crt",
    "InvalidonlySomeReasonsTest21EE.crt",
    "InvalidpathLenConstraintTest10EE.crt",
    "InvalidpathLenConstraintTest11EE.crt",
    "InvalidpathLenConstraintTest12EE.crt",
    "InvalidpathLenConstraintTest5EE.crt",
    "InvalidpathLenConstraintTest6EE.crt",
    "InvalidpathLenConstraintTest9EE.crt",
    "Invalidpre2000CRLnextUpdateTest12EE.crt",
    "Invalidpre2000UTCEEnotAfterDateTest7EE.crt",
    "InvalidrequireExplicitPolicyTest3EE.crt",
    "InvalidrequireExplicitPolicyTest5EE.crt",
    "OverlappingPoliciesTest6EE.crt",
    "UserNoticeQualifierTest15EE.crt",
    "UserNoticeQualifierTest16EE.crt",
    "UserNoticeQualifierTest17EE.crt",
    "UserNoticeQualifierTest19EE.crt",
    "ValidBasicSelfIssuedCRLSigningKeyTest6EE.crt",
    "ValidBasicSelfIssuedNewWithOldTest3EE.crt",
    "ValidBasicSelfIssuedNewWithOldTest4EE.crt",
    "ValidBasicSelfIssuedOldWithNewTest1EE.crt",
    "ValidCertificatePathTest1EE.crt",
    "ValidDNSnameConstraintsTest30EE.crt",
    "ValidDNSnameConstraintsTest32EE.crt",
    "ValidDNandRFC822nameConstraintsTest27EE.crt",
    "ValidDNnameConstraintsTest11EE.crt",
    "ValidDNnameConstraintsTest14EE.crt",
    "ValidDNnameConstraintsTest18EE.crt",
    "ValidDNnameConstraintsTest19EE.crt",
    "ValidDNnameConstraintsTest1EE.crt",
    "ValidDNnameConstraintsTest4EE.crt",
    "ValidDNnameConstraintsTest5EE.crt",
    "ValidDNnameConstraintsTest6EE.crt",
    "ValidDSAParameterInheritanceTest5EE.crt",
    "ValidDSASignaturesTest4EE.crt",
    "ValidGeneralizedTimeCRLnextUpdateTest13EE.crt",
    "ValidGeneralizedTimenotAfterDateTest8EE.crt",
    "ValidGeneralizedTimenotBeforeDateTest4EE.crt",
    "ValidIDPwithindirectCRLTest22EE.crt",
    "ValidIDPwithindirectCRLTest24EE.crt",
    "ValidIDPwithindirectCRLTest25EE.crt",
    "ValidLongSerialNumberTest16EE.crt",
    "ValidLongSerialNumberTest17EE.crt",
    "ValidNameChainingCapitalizationTest5EE.crt",
    "ValidNameChainingWhitespaceTest3EE.crt",
    "ValidNameChainingWhitespaceTest4EE.crt",
    "ValidNameUIDsTest6EE.crt",
    "ValidNegativeSerialNumberTest14EE.crt",
    "ValidNoissuingDistributionPointTest10EE.crt",
    "ValidPolicyMappingTest11EE.crt",
    "ValidPolicyMappingTest13EE.crt",
    "ValidPolicyMappingTest14EE.crt",
    "ValidPolicyMappingTest9EE.crt",
    "ValidRFC3280MandatoryAttributeTypesTest7EE.crt",
    "ValidRFC3280OptionalAttributeTypesTest8EE.crt",
    "ValidRFC822nameConstraintsTest21EE.crt",
    "ValidRFC822nameConstraintsTest23EE.crt",
    "ValidRFC822nameConstraintsTest25EE.crt",
    "ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt",
    "ValidSelfIssuedinhibitAnyPolicyTest7EE.crt",
    "ValidSelfIssuedinhibitAnyPolicyTest9EE.crt",
    "ValidSelfIssuedinhibitPolicyMappingTest7EE.crt",
    "ValidSelfIssuedpathLenConstraintTest15EE.crt",
    "ValidSelfIssuedpathLenConstraintTest17EE.crt",
    "ValidSelfIssuedrequireExplicitPolicyTest6EE.crt",
    "ValidSeparateCertificateandCRLKeysTest19EE.crt",
    "ValidTwoCRLsTest7EE.crt",
    "ValidURInameConstraintsTest34EE.crt",
    "ValidURInameConstraintsTest36EE.crt",
    "ValidUTF8StringCaseInsensitiveMatchTest11EE.crt",
    "ValidUTF8StringEncodedNamesTest9EE.crt",
    "ValidUnknownNotCriticalCertificateExtensionTest1EE.crt",
    "ValidbasicConstraintsNotCriticalTest4EE.crt",
    "ValidcRLIssuerTest28EE.crt",
    "ValidcRLIssuerTest29EE.crt",
    "ValidcRLIssuerTest30EE.crt",
    "ValidcRLIssuerTest33EE.crt",
    "ValiddeltaCRLTest2EE.crt",
    "ValiddeltaCRLTest5EE.crt",
    "ValiddeltaCRLTest7EE.crt",
    "ValiddeltaCRLTest8EE.crt",
    "ValiddistributionPointTest1EE.crt",
    "ValiddistributionPointTest4EE.crt",
    "ValiddistributionPointTest5EE.crt",
    "ValiddistributionPointTest7EE.crt",
    "ValidinhibitAnyPolicyTest2EE.crt",
    "ValidinhibitPolicyMappingTest2EE.crt",
    "ValidinhibitPolicyMappingTest4EE.crt",
    "ValidkeyUsageNotCriticalTest3EE.crt",
    "ValidonlyContainsCACertsTest13EE.crt",
    "ValidonlySomeReasonsTest18EE.crt",
    "ValidonlySomeReasonsTest19EE.crt",
    "ValidpathLenConstraintTest13EE.crt",
    "ValidpathLenConstraintTest14EE.crt",
    "ValidpathLenConstraintTest7EE.crt",
    "ValidpathLenConstraintTest8EE.crt",
    "Validpre2000UTCnotBeforeDateTest3EE.crt",
    "ValidrequireExplicitPolicyTest1EE.crt",
    "ValidrequireExplicitPolicyTest2EE.crt",
    "ValidrequireExplicitPolicyTest4EE.crt",
    "inhibitAnyPolicyTest3EE.crt"
]

def make_folders_for_sorting(dest):
    list = ["default", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]

    for name in list:
        new_dir = os.path.join(dest, name)
        try:
            os.stat(new_dir)
        except:
            os.mkdir(new_dir)


def put_in_sorted(dest, src):
    filename = os.path.basename(src)
    for key in sorted_pkits.keys():
        if filename in sorted_pkits[key]:
            new_spot = os.path.join(dest, key, os.path.basename(src))
            copyfile(src, new_spot)

broken_signatures = ['BadSignedCACert.crt','InvalidEESignatureTest3EE.crt']
broken_crl_signatures = ['BadCRLSignatureCACRL.crl']

def main():
    parser = OptionParser()
    parser.add_option("-a", "--originalPkitsFolder", dest="orig_pkits_folder", default="",
                      help="Folder containing certpairs, certs, crls, pkcs12 and smime folders")
    parser.add_option("-b", "--clonedPkitsFolder", dest="cloned_pkits_folder", default="",
                      help="Folder containined cloned PKITS artifacts exported from PCP")
    parser.add_option("-c", "--renamedClonedPkitsFolder", dest="renamed_cloned_pkits_folder", default="",
                      help="Folder to receive renamed PKITS artifacts")

    (options, args) = parser.parse_args()

    if options.orig_pkits_folder and options.cloned_pkits_folder and options.renamed_cloned_pkits_folder:
        orig_cert_files = glob2.glob(options.orig_pkits_folder + '/certs/*.crt')

        orig_dict = {}
        for filename in orig_cert_files:
            openssl_command = OPENSSL_EXE + " x509 -inform DER -noout -serial -in '" + filename + "'"
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            subject = line.decode("utf-8").replace("subject= ", "").strip()

            openssl_command = OPENSSL_EXE + " x509 -inform DER -noout -issuer -in '" + filename + "'"
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            issuer = line.decode("utf-8").replace("issuer= ", "").strip()

            orig_dict[subject+issuer] = os.path.basename(filename)

        dest_folder = options.renamed_cloned_pkits_folder

        make_folders_for_sorting(dest_folder)

        cloned_cert_files = glob2.glob(options.cloned_pkits_folder + '*.crt')
        for filename in cloned_cert_files:
            openssl_command = OPENSSL_EXE + " x509 -inform DER -noout -serial -in '" + filename + "'"
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            subject = line.decode("utf-8").replace("subject= ", "").strip()

            openssl_command = OPENSSL_EXE + " x509 -inform DER -noout -issuer -in '" + filename + "'"
            p = Popen(openssl_command, shell=True, stdout=PIPE)
            line = p.stdout.readline()
            issuer = line.decode("utf-8").replace("issuer= ", "").strip()

            orig_name =  orig_dict[subject+issuer]
            dest_file = os.path.join(dest_folder, orig_name)
            copyfile(filename, dest_file)

            if orig_name in broken_signatures:
                with open(dest_file, mode='rb') as file:
                    fileContent = bytearray(file.read())
                    num_bytes = len(fileContent)
                    if fileContent[num_bytes-1] == 0xFF:
                        fileContent[num_bytes-1] = 0xFE
                    else:
                        fileContent[num_bytes-1] = 0xFF
                    file.close()
                    fw = open(dest_file, mode='wb')
                    fw.write(fileContent)
                    fw.close()

            put_in_sorted(dest_folder, dest_file)


if __name__ == '__main__':
    main()