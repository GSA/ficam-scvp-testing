//
//  main.cpp
//  RhUtilsTest
//
//  Created by Carl Wallace on 10/17/11.
//  Copyright (c) 2011 Red Hound Software, Inc. All rights reserved.
//

#include <iostream>

//boost includes
#include "boost/filesystem/path.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/thread/recursive_mutex.hpp"
#include "boost/regex.hpp"
namespace fs = boost::filesystem;
#include "boost/shared_ptr.hpp"

/**
 DECLARE_SMART_PTR and FD_SMART_PTR are convenience macros for defining
 instances of boost::shared_ptr.
 */
#define DECLARE_SMART_PTR(c) \
typedef boost::shared_ptr<c> c##Ptr;

#define FD_SMART_PTR(c) \
class c; \
typedef boost::shared_ptr<c> c##Ptr


//STL includes
#include <fstream>

#include "ScvpScriptGenerator.h"

class PkitsTestCase
{
private:
    
public:
    PkitsTestCase()
    {
        taCertFileName = "TrustAnchorRootCertificate.crt";
        targetFileName = NULL;
        errorCode = 0;
        altTestName = NULL;
    }
    
    const char* taCertFileName;
    std::vector<const char*> intermediateCaNames;
    const char* targetFileName;
    const char* altTestName;
    int errorCode;
};
DECLARE_SMART_PTR(PkitsTestCase);

//float is set to section number, index into array gives subsection (adjusted for zero-based indexing)
std::map<std::string, std::vector<PkitsTestCasePtr> > g_pkitsDataMap;
std::map<std::string, std::vector<std::string> > g_pkitsSettingsMap;

#define CERTIFICATION_PATHS_ERROR_BASE  25000
enum
{
    NAME_CHAINING_FAILURE           = CERTIFICATION_PATHS_ERROR_BASE + 1,
    SIGNATURE_VERIFICATION_FAILURE,
    INVALID_NOT_BEFORE_DATE,
    INVALID_NOT_AFTER_DATE,
    MISSING_BASIC_CONSTRAINTS,
    INVALID_BASIC_CONSTRAINTS,
    INVALID_PATH_LENGTH,
    INVALID_KEY_USAGE,
    NULL_POLICY_SET,
    NAME_CONSTRAINTS_VIOLATION,
    UNPROCESSED_CRITICAL_EXTENSION,
    CCC_UNAUTH_TA,
    CCC_VIOLATION,
    MISSING_TRUST_ANCHOR,
    MISSING_TRUST_ANCHOR_NAME,
    PROHIBITED_ALG,
    PROHIBITED_KEY_SIZE,
    ENCODING_ERROR,
    MISSING_CERTIFICATE,
    UNEXPECTED_CONTENT_TYPE,
    SEQ_NUM_VIOLATION,
    NO_PATHS_FOUND,
    COUNTRY_CODE_VIOLATION,
    CERTIFICATE_REVOKED,
    REVOCATION_STATUS_NOT_DETERMINED,
    CERTIFICATE_ON_HOLD,
    CERTIFICATE_BLACKLISTED,
    STATUS_CHECK_RELIED_ON_STALE_CRL,
    REVOCATION_STATUS_NOT_AVAILABLE
};

void UnloadPkitsData()
{
    g_pkitsDataMap.clear();
    g_pkitsSettingsMap.clear();
}

void LoadPkits(const std::string& folder)
{
    if(!g_pkitsDataMap.empty())
        return;
    
    //-----------------------------------------------------------------------------
    //Section 4.1 - signature verification - 6 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidCertificatePathTest1EE.crt";
        g_pkitsDataMap["4.1"].push_back(testCase);
        g_pkitsSettingsMap["4.1"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BadSigned");
        testCase->targetFileName = "InvalidCASignatureTest2EE.crt";
        testCase->errorCode = SIGNATURE_VERIFICATION_FAILURE;
        g_pkitsDataMap["4.1"].push_back(testCase);
        g_pkitsSettingsMap["4.1"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "InvalidEESignatureTest3EE.crt";
        testCase->errorCode = SIGNATURE_VERIFICATION_FAILURE;
        g_pkitsDataMap["4.1"].push_back(testCase);
        g_pkitsSettingsMap["4.1"].push_back("DefaultSettings");
    }
    /*
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("DSA");
        testCase->targetFileName = "ValidDSASignaturesTest4EE.crt";
        g_pkitsDataMap["4.1"].push_back(testCase);
        g_pkitsSettingsMap["4.1"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("DSA");
        testCase->intermediateCaNames.push_back("DSAParametersInherited");
        testCase->targetFileName = "ValidDSAParameterInheritanceTest5EE.crt";
        g_pkitsDataMap["4.1"].push_back(testCase);
        g_pkitsSettingsMap["4.1"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("DSA");
        testCase->targetFileName = "InvalidDSASignatureTest6EE.crt";
        testCase->errorCode = SIGNATURE_VERIFICATION_FAILURE;
        g_pkitsDataMap["4.1"].push_back(testCase);
        g_pkitsSettingsMap["4.1"].push_back("DefaultSettings");
    }
    */
    //-----------------------------------------------------------------------------
    //Section 4.2 - validity periods - 8 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BadnotBeforeDate");
        testCase->targetFileName = "InvalidCAnotBeforeDateTest1EE.crt";
        testCase->errorCode = INVALID_NOT_BEFORE_DATE;
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "InvalidEEnotBeforeDateTest2EE.crt";
        testCase->errorCode = INVALID_NOT_BEFORE_DATE;
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "Validpre2000UTCnotBeforeDateTest3EE.crt";
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidGeneralizedTimenotBeforeDateTest4EE.crt";
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BadnotAfterDate");
        testCase->targetFileName = "InvalidCAnotAfterDateTest5EE.crt";
        testCase->errorCode = INVALID_NOT_AFTER_DATE;
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "InvalidEEnotAfterDateTest6EE.crt";
        testCase->errorCode = INVALID_NOT_AFTER_DATE;
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "Invalidpre2000UTCEEnotAfterDateTest7EE.crt";
        testCase->errorCode = INVALID_NOT_AFTER_DATE;
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidGeneralizedTimenotAfterDateTest8EE.crt";
        g_pkitsDataMap["4.2"].push_back(testCase);
        g_pkitsSettingsMap["4.2"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.3 - verifying name chaining - 10 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "InvalidNameChainingTest1EE.crt";
        testCase->errorCode = NAME_CHAINING_FAILURE;
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("NameOrdering");
        testCase->targetFileName = "InvalidNameChainingTest1EE.crt";
        testCase->errorCode = NAME_CHAINING_FAILURE;
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidNameChainingWhitespaceTest3EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidNameChainingWhitespaceTest4EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidNameChainingCapitalizationTest5EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("UID");
        testCase->targetFileName = "ValidNameUIDsTest6EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("RFC3280MandatoryAttributeTypes");
        testCase->targetFileName = "ValidRFC3280MandatoryAttributeTypesTest7EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("RFC3280OptionalAttributeTypes");
        testCase->targetFileName = "ValidRFC3280OptionalAttributeTypesTest8EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("UTF8StringEncodedNames");
        testCase->targetFileName = "ValidUTF8StringEncodedNamesTest9EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("RolloverfromPrintableStringtoUTF8String");
        testCase->targetFileName = "ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("UTF8StringCaseInsensitiveMatch");
        testCase->targetFileName = "ValidUTF8StringCaseInsensitiveMatchTest11EE.crt";
        g_pkitsDataMap["4.3"].push_back(testCase);
        g_pkitsSettingsMap["4.3"].push_back("DefaultSettings");
    }    
    
    //-----------------------------------------------------------------------------
    //Section 4.4 - basic certificate revocation - 21 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("NoCRLCA");
        testCase->targetFileName = "InvalidMissingCRLTest1EE.crt";
        testCase->altTestName = "4.4.1";
        testCase->errorCode = REVOCATION_STATUS_NOT_AVAILABLE;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("GoodCA");
        testCase->intermediateCaNames.push_back("RevokedsubCA");
        testCase->targetFileName = "InvalidRevokedCATest2EE.crt";
        testCase->altTestName = "4.4.2";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("GoodCA");
        testCase->targetFileName = "InvalidRevokedEETest3EE.crt";
        testCase->altTestName = "4.4.3";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BadCRLSignatureCA");
        testCase->targetFileName = "InvalidBadCRLSignatureTest4EE.crt";
        testCase->altTestName = "4.4.4";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BadCRLIssuerName");
        testCase->targetFileName = "InvalidBadCRLIssuerNameTest5EE.crt";
        testCase->altTestName = "4.4.5";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("WrongCRLCA");
        testCase->targetFileName = "InvalidWrongCRLTest6EE.crt";
        testCase->altTestName = "4.4.6";
        testCase->errorCode = REVOCATION_STATUS_NOT_AVAILABLE;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("TwoCRLsCA");
        testCase->targetFileName = "ValidTwoCRLsTest7EE.crt";
        testCase->altTestName = "4.4.7";
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("UnknownCRLEntryExtensionCA");
        testCase->targetFileName = "InvalidUnknownCRLEntryExtensionTest8EE.crt";
        testCase->altTestName = "4.4.8";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("UnknownCRLExtensionCA");
        testCase->targetFileName = "InvalidUnknownCRLExtensionTest9EE.crt";
        testCase->altTestName = "4.4.9";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("UnknownCRLExtensionCA");
        testCase->targetFileName = "InvalidUnknownCRLExtensionTest10EE.crt";
        testCase->altTestName = "4.4.10";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("OldCRLnextUpdateCA");
        testCase->targetFileName = "InvalidOldCRLnextUpdateTest11EE.crt";
        testCase->altTestName = "4.4.11";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pre2000CRLnextUpdateCA");
        testCase->targetFileName = "Invalidpre2000CRLnextUpdateTest12EE.crt";
        testCase->altTestName = "4.4.12";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("GeneralizedTimeCRLnextUpdateCA");
        testCase->targetFileName = "ValidGeneralizedTimeCRLnextUpdateTest13EE.crt";
        testCase->altTestName = "4.4.13";
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("NegativeSerialNumberCA");
        testCase->targetFileName = "ValidNegativeSerialNumberTest14EE.crt";
        testCase->altTestName = "4.4.14";
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("NegativeSerialNumberCA");
        testCase->targetFileName = "InvalidNegativeSerialNumberTest15EE.crt";
        testCase->altTestName = "4.4.15";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("LongSerialNumberCA");
        testCase->targetFileName = "ValidLongSerialNumberTest16EE.crt";
        testCase->altTestName = "4.4.16";
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("LongSerialNumberCA");
        testCase->targetFileName = "ValidLongSerialNumberTest17EE.crt";
        testCase->altTestName = "4.4.17";
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("LongSerialNumberCA");
        testCase->targetFileName = "InvalidLongSerialNumberTest18EE.crt";
        testCase->altTestName = "4.4.18";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("SeparateCertificateandCRLKeysCertificateSigningCA");
        testCase->targetFileName = "ValidSeparateCertificateandCRLKeysTest19EE.crt";
        testCase->altTestName = "4.4.19";
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("SeparateCertificateandCRLKeysCertificateSigningCA");
        testCase->targetFileName = "InvalidSeparateCertificateandCRLKeysTest20EE.crt";
        testCase->altTestName = "4.4.20";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("SeparateCertificateandCRLKeysCA2CertificateSigningCA");
        testCase->targetFileName = "InvalidSeparateCertificateandCRLKeysTest21EE.crt";
        testCase->altTestName = "4.4.21";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.4"].push_back(testCase);
        g_pkitsSettingsMap["4.4"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.5 - verifying paths with self-issued certificates - 8 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedNewKeyCA");
        testCase->intermediateCaNames.push_back("BasicSelfIssuedNewKeyOldWithNewCA");
        testCase->targetFileName = "ValidBasicSelfIssuedOldWithNewTest1EE.crt";
        testCase->altTestName = "4.5.1";
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedNewKeyCA");
        testCase->intermediateCaNames.push_back("BasicSelfIssuedNewKeyOldWithNewCA");
        testCase->targetFileName = "InvalidBasicSelfIssuedOldWithNewTest2EE.crt";
        testCase->altTestName = "4.5.2";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedOldKeyCA");
        testCase->intermediateCaNames.push_back("BasicSelfIssuedOldKeyNewWithOldCA");
        testCase->targetFileName = "ValidBasicSelfIssuedNewWithOldTest3EE.crt";
        testCase->altTestName = "4.5.3";
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedOldKeyCA");
        testCase->targetFileName = "ValidBasicSelfIssuedNewWithOldTest4EE.crt";
        testCase->altTestName = "4.5.4";
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedOldKeyCA");
        testCase->targetFileName = "InvalidBasicSelfIssuedNewWithOldTest5EE.crt";
        testCase->altTestName = "4.5.5";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedCRLSigningKeyCA");
        testCase->targetFileName = "ValidBasicSelfIssuedCRLSigningKeyTest6EE.crt";
        testCase->altTestName = "4.5.6";
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedCRLSigningKeyCA");
        testCase->targetFileName = "InvalidBasicSelfIssuedCRLSigningKeyTest7EE.crt";
        testCase->altTestName = "4.5.7";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("BasicSelfIssuedCRLSigningKeyCRL");
        testCase->targetFileName = "InvalidBasicSelfIssuedCRLSigningKeyTest8EE.crt";
        testCase->altTestName = "4.5.8";
        testCase->errorCode = MISSING_BASIC_CONSTRAINTS;
        g_pkitsDataMap["4.5"].push_back(testCase);
        g_pkitsSettingsMap["4.5"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.6 - verifying basic constraints - 17 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("MissingbasicConstraints");
        testCase->targetFileName = "InvalidMissingbasicConstraintsTest1EE.crt";
        testCase->errorCode = MISSING_BASIC_CONSTRAINTS;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("basicConstraintsCriticalcAFalse");
        testCase->targetFileName = "InvalidcAFalseTest2EE.crt";
        testCase->errorCode = INVALID_BASIC_CONSTRAINTS;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("basicConstraintsNotCriticalcAFalse");
        testCase->targetFileName = "InvalidcAFalseTest3EE.crt";
        testCase->errorCode = INVALID_BASIC_CONSTRAINTS;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("basicConstraintsNotCritical");
        testCase->targetFileName = "ValidbasicConstraintsNotCriticalTest4EE.crt";
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint0");
        testCase->intermediateCaNames.push_back("pathLenConstraint0sub");
        testCase->targetFileName = "InvalidpathLenConstraintTest5EE.crt";
        testCase->errorCode = INVALID_PATH_LENGTH;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint0");
        testCase->intermediateCaNames.push_back("pathLenConstraint0sub");
        testCase->intermediateCaNames.push_back("pathLenConstraint0subCA2");
        testCase->targetFileName = "InvalidpathLenConstraintTest6EE.crt";
        testCase->errorCode = INVALID_PATH_LENGTH;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint0");
        testCase->targetFileName = "ValidpathLenConstraintTest7EE.crt";
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint0");
        testCase->targetFileName = "ValidpathLenConstraintTest8EE.crt";
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint6");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subCA0");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubCA00");
        testCase->targetFileName = "InvalidpathLenConstraintTest9EE.crt";
        testCase->errorCode = INVALID_PATH_LENGTH;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {//4.6.10
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint6");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subCA0");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubCA00");
        testCase->targetFileName = "InvalidpathLenConstraintTest10EE.crt";
        testCase->errorCode = INVALID_PATH_LENGTH;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint6");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subCA1");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubCA11");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubsubCA11X");
        testCase->targetFileName = "InvalidpathLenConstraintTest11EE.crt";
        testCase->errorCode = INVALID_PATH_LENGTH;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint6");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subCA1");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubCA11");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubsubCA11X");
        testCase->targetFileName = "InvalidpathLenConstraintTest12EE.crt";
        testCase->errorCode = INVALID_PATH_LENGTH;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint6");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subCA4");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubCA41");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubsubCA41X");
        testCase->targetFileName = "ValidpathLenConstraintTest13EE.crt";
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint6");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subCA4");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubCA41");
        testCase->intermediateCaNames.push_back("pathLenConstraint6subsubsubCA41X");
        testCase->targetFileName = "ValidpathLenConstraintTest14EE.crt";
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint0");
        testCase->intermediateCaNames.push_back("pathLenConstraint0SelfIssued");
        testCase->targetFileName = "ValidSelfIssuedpathLenConstraintTest15EE.crt";
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint0");
        testCase->intermediateCaNames.push_back("pathLenConstraint0SelfIssued");
        testCase->intermediateCaNames.push_back("pathLenConstraint0subCA2");
        testCase->targetFileName = "InvalidSelfIssuedpathLenConstraintTest16EE.crt";
        testCase->errorCode = INVALID_PATH_LENGTH;
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("pathLenConstraint1");
        testCase->intermediateCaNames.push_back("pathLenConstraint1SelfIssued");
        testCase->intermediateCaNames.push_back("pathLenConstraint1subCA");
        testCase->intermediateCaNames.push_back("pathLenConstraint1SelfIssuedsubCA");
        testCase->targetFileName = "ValidSelfIssuedpathLenConstraintTest17EE.crt";
        g_pkitsDataMap["4.6"].push_back(testCase);
        g_pkitsSettingsMap["4.6"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.7 - key usage - 5 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("keyUsageCriticalkeyCertSignFalse");
        testCase->targetFileName = "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt";
        testCase->errorCode = INVALID_KEY_USAGE;
        g_pkitsDataMap["4.7"].push_back(testCase);
        g_pkitsSettingsMap["4.7"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("keyUsageNotCriticalkeyCertSignFalse");
        testCase->targetFileName = "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt";
        testCase->errorCode = INVALID_KEY_USAGE;
        g_pkitsDataMap["4.7"].push_back(testCase);
        g_pkitsSettingsMap["4.7"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("keyUsageNotCritical");
        testCase->targetFileName = "ValidkeyUsageNotCriticalTest3EE.crt";
        g_pkitsDataMap["4.7"].push_back(testCase);
        g_pkitsSettingsMap["4.7"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("keyUsageCriticalcRLSignFalse");
        testCase->targetFileName = "InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt";
        testCase->errorCode = INVALID_KEY_USAGE;
        g_pkitsDataMap["4.7"].push_back(testCase);
        g_pkitsSettingsMap["4.7"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("keyUsageNotCriticalcRLSignFalse");
        testCase->targetFileName = "InvalidkeyUsageNotCriticalcRLSignFalseTest5EE.crt";
        testCase->errorCode = INVALID_KEY_USAGE;
        g_pkitsDataMap["4.7"].push_back(testCase);
        g_pkitsSettingsMap["4.7"].push_back("DefaultSettings");
    }
 
    //-----------------------------------------------------------------------------
    //Section 4.8 - certificate policies - 20 tests (plus subtests)
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidCertificatePathTest1EE.crt";
        testCase->altTestName = "4.8.1.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings1");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidCertificatePathTest1EE.crt";
        testCase->altTestName = "4.8.1.2";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings2");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidCertificatePathTest1EE.crt";
        testCase->altTestName = "4.8.1.3";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings3");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "ValidCertificatePathTest1EE.crt";
        testCase->altTestName = "4.8.1.4";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings4");
    }
    
    {//4.8.2
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("NoPolicies");
        testCase->targetFileName = "AllCertificatesNoPoliciesTest2EE.crt";
        testCase->altTestName = "4.8.2.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("NoPolicies");
        testCase->targetFileName = "AllCertificatesNoPoliciesTest2EE.crt";
        testCase->altTestName = "4.8.2.2";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings1");
    }
    
    {//4.8.3
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->intermediateCaNames.push_back("PoliciesP2sub");
        testCase->targetFileName = "DifferentPoliciesTest3EE.crt";
        testCase->altTestName = "4.8.3.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->intermediateCaNames.push_back("PoliciesP2sub");
        testCase->targetFileName = "DifferentPoliciesTest3EE.crt";
        testCase->altTestName = "4.8.3.2";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings1");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->intermediateCaNames.push_back("PoliciesP2sub");
        testCase->targetFileName = "DifferentPoliciesTest3EE.crt";
        testCase->altTestName = "4.8.3.3";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings4");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->intermediateCaNames.push_back("Goodsub");
        testCase->targetFileName = "DifferentPoliciesTest4EE.crt";
        testCase->altTestName = "4.8.4";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->intermediateCaNames.push_back("PoliciesP2subCA2");
        testCase->targetFileName = "DifferentPoliciesTest5EE.crt";
        testCase->altTestName = "4.8.5";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    
    {//4.8.6
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP1234");
        testCase->intermediateCaNames.push_back("PoliciesP1234subCAP123");
        testCase->intermediateCaNames.push_back("PoliciesP1234subsubCAP123P12");
        testCase->targetFileName = "OverlappingPoliciesTest6EE.crt";
        testCase->altTestName = "4.8.6.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP1234");
        testCase->intermediateCaNames.push_back("PoliciesP1234subCAP123");
        testCase->intermediateCaNames.push_back("PoliciesP1234subsubCAP123P12");
        testCase->targetFileName = "OverlappingPoliciesTest6EE.crt";
        testCase->altTestName = "4.8.6.2";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP1234");
        testCase->intermediateCaNames.push_back("PoliciesP1234subCAP123");
        testCase->intermediateCaNames.push_back("PoliciesP1234subsubCAP123P12");
        testCase->targetFileName = "OverlappingPoliciesTest6EE.crt";
        testCase->altTestName = "4.8.6.3";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings6");
    }
    
    {//4.8.7
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP123");
        testCase->intermediateCaNames.push_back("PoliciesP123subCAP12");
        testCase->intermediateCaNames.push_back("PoliciesP123subsubCAP12P1");
        testCase->targetFileName = "DifferentPoliciesTest7EE.crt";
        testCase->altTestName = "4.8.7";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP12");
        testCase->intermediateCaNames.push_back("PoliciesP12subCAP1");
        testCase->intermediateCaNames.push_back("PoliciesP12subsubCAP1P2");
        testCase->targetFileName = "DifferentPoliciesTest8EE.crt";
        testCase->altTestName = "4.8.8";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP123");
        testCase->intermediateCaNames.push_back("PoliciesP123subCAP12");
        testCase->intermediateCaNames.push_back("PoliciesP123subsubCAP12P2");
        testCase->intermediateCaNames.push_back("PoliciesP123subsubsubCAP12P2P1");
        testCase->targetFileName = "DifferentPoliciesTest9EE.crt";
        testCase->altTestName = "4.8.9";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    
    {//4.8.10
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP12");
        testCase->targetFileName = "AllCertificatesSamePoliciesTest10EE.crt";
        testCase->altTestName = "4.8.10.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP12");
        testCase->targetFileName = "AllCertificatesSamePoliciesTest10EE.crt";
        testCase->altTestName = "4.8.10.2";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP12");
        testCase->targetFileName = "AllCertificatesSamePoliciesTest10EE.crt";
        testCase->altTestName = "4.8.10.3";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings6");
    }
    
    {//4.8.11
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("anyPolicy");
        testCase->targetFileName = "AllCertificatesanyPolicyTest11EE.crt";
        testCase->altTestName = "4.8.11.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("anyPolicy");
        testCase->targetFileName = "AllCertificatesanyPolicyTest11EE.crt";
        testCase->altTestName = "4.8.11.2";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings5");
    }
    
    {//4.8.12
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP3");
        testCase->targetFileName = "DifferentPoliciesTest12EE.crt";
        testCase->altTestName = "4.8.12";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    
    {//4.8.13
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP123");
        testCase->targetFileName = "AllCertificatesSamePoliciesTest13EE.crt";
        testCase->altTestName = "4.8.13.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP123");
        testCase->targetFileName = "AllCertificatesSamePoliciesTest13EE.crt";
        testCase->altTestName = "4.8.13.2";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings6");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP123");
        testCase->targetFileName = "AllCertificatesSamePoliciesTest13EE.crt";
        testCase->altTestName = "4.8.13.3";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings7");
    }
    
    {//4.8.14
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("anyPolicy");
        testCase->targetFileName = "AnyPolicyTest14EE.crt";
        testCase->altTestName = "4.8.14.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("anyPolicy");
        testCase->targetFileName = "AnyPolicyTest14EE.crt";
        testCase->altTestName = "4.8.14.2";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings6");
    }
    
    {//4.8.15
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->targetFileName = "UserNoticeQualifierTest15EE.crt";
        testCase->altTestName = "4.8.15";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "UserNoticeQualifierTest16EE.crt";
        testCase->altTestName = "4.8.16";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "UserNoticeQualifierTest17EE.crt";
        testCase->altTestName = "4.8.17";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    
    {//4.8.18
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP12");
        testCase->targetFileName = "UserNoticeQualifierTest18EE.crt";
        testCase->altTestName = "4.8.18.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PoliciesP12");
        testCase->targetFileName = "UserNoticeQualifierTest18EE.crt";
        testCase->altTestName = "4.8.18.2";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings6");
    }
    
    {//4.8.19
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->targetFileName = "UserNoticeQualifierTest19EE.crt";
        testCase->altTestName = "4.8.19";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    
    {//4.8.20
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "CPSPointerQualifierTest20EE.crt";
        testCase->altTestName = "4.8.20.1";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->targetFileName = "CPSPointerQualifierTest20EE.crt";
        testCase->altTestName = "4.8.20.2";
        g_pkitsDataMap["4.8"].push_back(testCase);
        g_pkitsSettingsMap["4.8"].push_back("Settings1");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.9 - require explicit policy - 8 tests
    //-----------------------------------------------------------------------------
#pragma mark Section 4.9
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy10");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy10sub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy10subsub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy10subsubsub");
        testCase->targetFileName = "ValidrequireExplicitPolicyTest1EE.crt";
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy5");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy5sub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy5subsub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy5subsubsub");
        testCase->targetFileName = "ValidrequireExplicitPolicyTest2EE.crt";
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy4");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy4sub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy4subsub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy4subsubsub");
        testCase->targetFileName = "InvalidrequireExplicitPolicyTest3EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy0");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy0sub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy0subsub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy0subsubsub");
        testCase->targetFileName = "ValidrequireExplicitPolicyTest4EE.crt";
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy7");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy7subCARE2");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy7subsubCARE2RE4");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy7subsubsubCARE2RE4");
        testCase->targetFileName = "InvalidrequireExplicitPolicyTest5EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2SelfIssued");
        testCase->targetFileName = "ValidSelfIssuedrequireExplicitPolicyTest6EE.crt";
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2SelfIssued");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2sub");
        testCase->targetFileName = "InvalidSelfIssuedrequireExplicitPolicyTest7EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2SelfIssued");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2sub");
        testCase->intermediateCaNames.push_back("requireExplicitPolicy2SelfIssuedsub");
        testCase->targetFileName = "InvalidSelfIssuedrequireExplicitPolicyTest8EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.9"].push_back(testCase);
        g_pkitsSettingsMap["4.9"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.10 - policy mapping - 14 tests
    //-----------------------------------------------------------------------------
    {//4.10.1
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Mapping1to2");
        testCase->targetFileName = "ValidPolicyMappingTest1EE.crt";
        testCase->altTestName = "4.10.1.1";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Mapping1to2");
        testCase->targetFileName = "ValidPolicyMappingTest1EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.1.2";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings6");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Mapping1to2");
        testCase->targetFileName = "ValidPolicyMappingTest1EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.1.3";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings8");
    }
    
    {//4.10.2
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Mapping1to2");
        testCase->targetFileName = "InvalidPolicyMappingTest2EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.2.1";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Mapping1to2");
        testCase->targetFileName = "InvalidPolicyMappingTest2EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.2.2";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings8");
    }
    
    {//4.10.3
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P12Mapping1to3");
        testCase->intermediateCaNames.push_back("P12Mapping1to3sub");
        testCase->intermediateCaNames.push_back("P12Mapping1to3subsub");
        testCase->targetFileName = "ValidPolicyMappingTest3EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.3.1";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P12Mapping1to3");
        testCase->intermediateCaNames.push_back("P12Mapping1to3sub");
        testCase->intermediateCaNames.push_back("P12Mapping1to3subsub");
        testCase->targetFileName = "ValidPolicyMappingTest3EE.crt";
        testCase->altTestName = "4.10.3.2";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings6");
    }
    
    {//4.10.4
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P12Mapping1to3");
        testCase->intermediateCaNames.push_back("P12Mapping1to3sub");
        testCase->intermediateCaNames.push_back("P12Mapping1to3subsub");
        testCase->targetFileName = "InvalidPolicyMappingTest4EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.4.1";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings5");
    }
    
    {//4.10.5
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P1Mapping1to234");
        testCase->intermediateCaNames.push_back("P1Mapping1to234sub");
        testCase->targetFileName = "ValidPolicyMappingTest5EE.crt";
        testCase->altTestName = "4.10.5.1";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P1Mapping1to234");
        testCase->intermediateCaNames.push_back("P1Mapping1to234sub");
        testCase->targetFileName = "ValidPolicyMappingTest5EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.5.2";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings9");
    }
    
    {//4.10.6
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P1Mapping1to234");
        testCase->intermediateCaNames.push_back("P1Mapping1to234sub");
        testCase->targetFileName = "ValidPolicyMappingTest6EE.crt";
        testCase->altTestName = "4.10.6.1";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P1Mapping1to234");
        testCase->intermediateCaNames.push_back("P1Mapping1to234sub");
        testCase->targetFileName = "ValidPolicyMappingTest6EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.6.2";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings9");
    }
    
    {//4.10.7
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("MappingFromanyPolicy");
        testCase->targetFileName = "InvalidMappingFromanyPolicyTest7EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.7";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("MappingToanyPolicy");
        testCase->targetFileName = "InvalidMappingToanyPolicyTest8EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.8";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("PanyPolicyMapping1to2");
        testCase->targetFileName = "ValidPolicyMappingTest9EE.crt";
        testCase->altTestName = "4.10.9";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->intermediateCaNames.push_back("GoodsubCAPanyPolicyMapping1to2");
        testCase->targetFileName = "InvalidPolicyMappingTest10EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.10.10";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("Good");
        testCase->intermediateCaNames.push_back("GoodsubCAPanyPolicyMapping1to2");
        testCase->targetFileName = "ValidPolicyMappingTest11EE.crt";
        testCase->altTestName = "4.10.11";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    
    {//4.10.12
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P12Mapping1to3");
        testCase->targetFileName = "ValidPolicyMappingTest12EE.crt";
        testCase->altTestName = "4.10.12.1";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings5");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P12Mapping1to3");
        testCase->targetFileName = "ValidPolicyMappingTest12EE.crt";
        testCase->altTestName = "4.10.12.2";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("Settings6");
    }
    
    {//4.10.13
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P1anyPolicyMapping1to2");
        testCase->targetFileName = "ValidPolicyMappingTest13EE.crt";
        testCase->altTestName = "4.10.13";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("P1anyPolicyMapping1to2");
        testCase->targetFileName = "ValidPolicyMappingTest14EE.crt";
        testCase->altTestName = "4.10.14";
        g_pkitsDataMap["4.10"].push_back(testCase);
        g_pkitsSettingsMap["4.10"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.11 - inhibit policy mapping - 11 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping0");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping0sub");
        testCase->targetFileName = "InvalidinhibitPolicyMappingTest1EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.1";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12sub");
        testCase->targetFileName = "ValidinhibitPolicyMappingTest2EE.crt";
        testCase->altTestName = "4.11.2";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12sub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12subsub");
        testCase->targetFileName = "InvalidinhibitPolicyMappingTest3EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.3";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12sub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12subsub");
        testCase->targetFileName = "ValidinhibitPolicyMappingTest4EE.crt";
        testCase->altTestName = "4.11.4";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping5");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping5sub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping5subsub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping5subsubsub");
        testCase->targetFileName = "InvalidinhibitPolicyMappingTest5EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.5";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12subCAIPM5");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P12subsubCAIPM5");
        testCase->targetFileName = "InvalidinhibitPolicyMappingTest6EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.6";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1sub");
        testCase->targetFileName = "ValidSelfIssuedinhibitPolicyMappingTest7EE.crt";
        testCase->altTestName = "4.11.7";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1sub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1subsub");
        testCase->targetFileName = "InvalidSelfIssuedinhibitPolicyMappingTest8EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.8";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1sub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1subsub");
        testCase->targetFileName = "InvalidSelfIssuedinhibitPolicyMappingTest9EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.9";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1sub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1SelfIssuedsub");
        testCase->targetFileName = "InvalidSelfIssuedinhibitPolicyMappingTest10EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.10";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1sub");
        testCase->intermediateCaNames.push_back("inhibitPolicyMapping1P1SelfIssuedsub");
        testCase->targetFileName = "InvalidSelfIssuedinhibitPolicyMappingTest11EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.11.11";
        g_pkitsDataMap["4.11"].push_back(testCase);
        g_pkitsSettingsMap["4.11"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.12 - inhibit any policy - 10 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy0");
        testCase->targetFileName = "InvalidinhibitAnyPolicyTest1EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.12.1";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy0");
        testCase->targetFileName = "ValidinhibitAnyPolicyTest2EE.crt";
        testCase->altTestName = "4.12.2";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCA1");
        testCase->targetFileName = "inhibitAnyPolicyTest3EE.crt";
        testCase->altTestName = "4.12.3.1";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCA1");
        testCase->targetFileName = "inhibitAnyPolicyTest3EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.12.3.2";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("Settings10");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCA1");
        testCase->targetFileName = "InvalidinhibitAnyPolicyTest4EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.12.4";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy5");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy5sub");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy5subsub");
        testCase->targetFileName = "InvalidinhibitAnyPolicyTest5EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.12.5";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCAIAP5");
        testCase->targetFileName = "InvalidinhibitAnyPolicyTest6EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.12.6";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCA2");
        testCase->targetFileName = "ValidSelfIssuedinhibitAnyPolicyTest7EE.crt";
        testCase->altTestName = "4.12.7";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCA2");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subsubCA2");
        testCase->targetFileName = "InvalidSelfIssuedinhibitAnyPolicyTest8EE.crt";
        testCase->errorCode = NULL_POLICY_SET;
        testCase->altTestName = "4.12.8";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCA2");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1SelfIssuedsubCA2");
        testCase->targetFileName = "ValidSelfIssuedinhibitAnyPolicyTest9EE.crt";
        testCase->altTestName = "4.12.9";
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1SelfIssued");
        testCase->intermediateCaNames.push_back("inhibitAnyPolicy1subCA2");
        testCase->targetFileName = "InvalidSelfIssuedinhibitAnyPolicyTest10EE.crt";
        testCase->altTestName = "4.12.10";
        testCase->errorCode = NULL_POLICY_SET;
        g_pkitsDataMap["4.12"].push_back(testCase);
        g_pkitsSettingsMap["4.12"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.13 - name constraints - 38 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->targetFileName = "ValidDNnameConstraintsTest1EE.crt";
        testCase->altTestName = "4.13.1";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->targetFileName = "InvalidDNnameConstraintsTest2EE.crt";
        testCase->altTestName = "4.13.2";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->targetFileName = "InvalidDNnameConstraintsTest3EE.crt";
        testCase->altTestName = "4.13.3";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->targetFileName = "ValidDNnameConstraintsTest4EE.crt";
        testCase->altTestName = "4.13.4";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN2");
        testCase->targetFileName = "ValidDNnameConstraintsTest5EE.crt";
        testCase->altTestName = "4.13.5";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN3");
        testCase->targetFileName = "ValidDNnameConstraintsTest6EE.crt";
        testCase->altTestName = "4.13.6";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN3");
        testCase->targetFileName = "InvalidDNnameConstraintsTest7EE.crt";
        testCase->altTestName = "4.13.7";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN4");
        testCase->targetFileName = "InvalidDNnameConstraintsTest8EE.crt";
        testCase->altTestName = "4.13.8";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN4");
        testCase->targetFileName = "InvalidDNnameConstraintsTest9EE.crt";
        testCase->altTestName = "4.13.9";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN5");
        testCase->targetFileName = "InvalidDNnameConstraintsTest10EE.crt";
        testCase->altTestName = "4.13.10";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN5");
        testCase->targetFileName = "ValidDNnameConstraintsTest11EE.crt";
        testCase->altTestName = "4.13.11";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1subCA1");
        testCase->targetFileName = "InvalidDNnameConstraintsTest12EE.crt";
        testCase->altTestName = "4.13.12";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1subCA2");
        testCase->targetFileName = "InvalidDNnameConstraintsTest13EE.crt";
        testCase->altTestName = "4.13.13";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1subCA2");
        testCase->targetFileName = "ValidDNnameConstraintsTest14EE.crt";
        testCase->altTestName = "4.13.14";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN3");
        testCase->intermediateCaNames.push_back("nameConstraintsDN3subCA1");
        testCase->targetFileName = "InvalidDNnameConstraintsTest15EE.crt";
        testCase->altTestName = "4.13.15";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN3");
        testCase->intermediateCaNames.push_back("nameConstraintsDN3subCA1");
        testCase->targetFileName = "InvalidDNnameConstraintsTest16EE.crt";
        testCase->altTestName = "4.13.16";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN3");
        testCase->intermediateCaNames.push_back("nameConstraintsDN3subCA2");
        testCase->targetFileName = "InvalidDNnameConstraintsTest17EE.crt";
        testCase->altTestName = "4.13.17";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN3");
        testCase->intermediateCaNames.push_back("nameConstraintsDN3subCA2");
        testCase->targetFileName = "ValidDNnameConstraintsTest18EE.crt";
        testCase->altTestName = "4.13.18";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1SelfIssued");
        testCase->targetFileName = "ValidDNnameConstraintsTest19EE.crt";
        testCase->altTestName = "4.13.19";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1SelfIssued");
        testCase->targetFileName = "InvalidDNnameConstraintsTest20EE.crt";
        testCase->altTestName = "4.13.20";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsRFC822CA1");
        testCase->targetFileName = "ValidRFC822nameConstraintsTest21EE.crt";
        testCase->altTestName = "4.13.21";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsRFC822CA1");
        testCase->targetFileName = "InvalidRFC822nameConstraintsTest22EE.crt";
        testCase->altTestName = "4.13.22";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsRFC822CA2");
        testCase->targetFileName = "ValidRFC822nameConstraintsTest23EE.crt";
        testCase->altTestName = "4.13.23";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsRFC822CA2");
        testCase->targetFileName = "InvalidRFC822nameConstraintsTest24EE.crt";
        testCase->altTestName = "4.13.24";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsRFC822CA3");
        testCase->targetFileName = "ValidRFC822nameConstraintsTest25EE.crt";
        testCase->altTestName = "4.13.25";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsRFC822CA3");
        testCase->targetFileName = "InvalidRFC822nameConstraintsTest26EE.crt";
        testCase->altTestName = "4.13.26";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1subCA3");
        testCase->targetFileName = "ValidDNandRFC822nameConstraintsTest27EE.crt";
        testCase->altTestName = "4.13.27";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1subCA3");
        testCase->targetFileName = "InvalidDNandRFC822nameConstraintsTest28EE.crt";
        testCase->altTestName = "4.13.28";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDN1");
        testCase->intermediateCaNames.push_back("nameConstraintsDN1subCA3");
        testCase->targetFileName = "InvalidDNandRFC822nameConstraintsTest29EE.crt";
        testCase->altTestName = "4.13.29";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDNS1");
        testCase->targetFileName = "ValidDNSnameConstraintsTest30EE.crt";
        testCase->altTestName = "4.13.30";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDNS1");
        testCase->targetFileName = "InvalidDNSnameConstraintsTest31EE.crt";
        testCase->altTestName = "4.13.31";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDNS2");
        testCase->targetFileName = "ValidDNSnameConstraintsTest32EE.crt";
        testCase->altTestName = "4.13.32";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDNS2");
        testCase->targetFileName = "InvalidDNSnameConstraintsTest33EE.crt";
        testCase->altTestName = "4.13.33";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsURI1");
        testCase->targetFileName = "ValidURInameConstraintsTest34EE.crt";
        testCase->altTestName = "4.13.34";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsURI1");
        testCase->targetFileName = "InvalidURInameConstraintsTest35EE.crt";
        testCase->altTestName = "4.13.35";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsURI2");
        testCase->targetFileName = "ValidURInameConstraintsTest36EE.crt";
        testCase->altTestName = "4.13.36";
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsURI2");
        testCase->targetFileName = "InvalidURInameConstraintsTest37EE.crt";
        testCase->altTestName = "4.13.37";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("nameConstraintsDNS1");
        testCase->targetFileName = "InvalidDNSnameConstraintsTest38EE.crt";
        testCase->altTestName = "4.13.38";
        testCase->errorCode = NAME_CONSTRAINTS_VIOLATION;
        g_pkitsDataMap["4.13"].push_back(testCase);
        g_pkitsSettingsMap["4.13"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.14 - distribution points - 35 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint1CA");
        testCase->targetFileName = "ValiddistributionPointTest1EE.crt";
        testCase->altTestName = "4.14.1";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint1CA");
        testCase->targetFileName = "InvaliddistributionPointTest2EE.crt";
        testCase->altTestName = "4.14.2";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint1CA");
        testCase->targetFileName = "InvaliddistributionPointTest3EE.crt";
        testCase->altTestName = "4.14.3";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint1CA");
        testCase->targetFileName = "ValiddistributionPointTest4EE.crt";
        testCase->altTestName = "4.14.4";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint2CA");
        testCase->targetFileName = "ValiddistributionPointTest5EE.crt";
        testCase->altTestName = "4.14.5";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint2CA");
        testCase->targetFileName = "InvaliddistributionPointTest6EE.crt";
        testCase->altTestName = "4.14.6";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint2CA");
        testCase->targetFileName = "ValiddistributionPointTest7EE.crt";
        testCase->altTestName = "4.14.7";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint2CA");
        testCase->targetFileName = "InvaliddistributionPointTest8EE.crt";
        testCase->altTestName = "4.14.8";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("distributionPoint2CA");
        testCase->targetFileName = "InvaliddistributionPointTest9EE.crt";
        testCase->altTestName = "4.14.9";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("NoissuingDistributionPointCA");
        testCase->targetFileName = "ValidNoissuingDistributionPointTest10EE.crt";
        testCase->altTestName = "4.14.10";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlyContainsUserCertsCA");
        testCase->targetFileName = "InvalidonlyContainsUserCertsTest11EE.crt";
        testCase->altTestName = "4.14.11";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlyContainsCACertsCA");
        testCase->targetFileName = "InvalidonlyContainsCACertsTest12EE.crt";
        testCase->altTestName = "4.14.12";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlyContainsCACertsCA");
        testCase->targetFileName = "ValidonlyContainsCACertsTest13EE.crt";
        testCase->altTestName = "4.14.13";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlyContainsAttributeCertsCA");
        testCase->targetFileName = "InvalidonlyContainsAttributeCertsTest14EE.crt";
        testCase->altTestName = "4.14.14";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlySomeReasonsCA1");
        testCase->targetFileName = "InvalidonlySomeReasonsTest15EE.crt";
        testCase->altTestName = "4.14.15";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlySomeReasonsCA1");
        testCase->targetFileName = "InvalidonlySomeReasonsTest16EE.crt";
        testCase->altTestName = "4.14.16";
        testCase->errorCode = CERTIFICATE_ON_HOLD;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlySomeReasonsCA2");
        testCase->targetFileName = "InvalidonlySomeReasonsTest17EE.crt";
        testCase->altTestName = "4.14.17";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlySomeReasonsCA3");
        testCase->targetFileName = "ValidonlySomeReasonsTest18EE.crt";
        testCase->altTestName = "4.14.18";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlySomeReasonsCA4");
        testCase->targetFileName = "ValidonlySomeReasonsTest19EE.crt";
        testCase->altTestName = "4.14.19";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlySomeReasonsCA4");
        testCase->targetFileName = "InvalidonlySomeReasonsTest20EE.crt";
        testCase->altTestName = "4.14.20";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("onlySomeReasonsCA4");
        testCase->targetFileName = "InvalidonlySomeReasonsTest21EE.crt";
        testCase->altTestName = "4.14.21";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA1");
        testCase->targetFileName = "ValidIDPwithindirectCRLTest22EE.crt";
        testCase->altTestName = "4.14.22";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA1");
        testCase->targetFileName = "InvalidIDPwithindirectCRLTest23EE.crt";
        testCase->altTestName = "4.14.23";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA2");
        testCase->targetFileName = "ValidIDPwithindirectCRLTest24EE.crt";
        testCase->altTestName = "4.14.24";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA2");
        testCase->targetFileName = "ValidIDPwithindirectCRLTest25EE.crt";
        testCase->altTestName = "4.14.25";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA2");
        testCase->targetFileName = "InvalidIDPwithindirectCRLTest26EE.crt";
        testCase->altTestName = "4.14.26";
        testCase->errorCode = REVOCATION_STATUS_NOT_AVAILABLE;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA2");
        testCase->targetFileName = "InvalidcRLIssuerTest27EE.crt";
        testCase->altTestName = "4.14.27";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA3");
        testCase->targetFileName = "ValidcRLIssuerTest28EE.crt";
        testCase->altTestName = "4.14.28";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA3");
        testCase->targetFileName = "ValidcRLIssuerTest29EE.crt";
        testCase->altTestName = "4.14.29";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA4");
        testCase->targetFileName = "ValidcRLIssuerTest30EE.crt";
        testCase->altTestName = "4.14.30";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;	//Changed the expected outcome because the test has a circular dependency
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA6");
        testCase->targetFileName = "InvalidcRLIssuerTest31EE.crt";
        testCase->altTestName = "4.14.31";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA6");
        testCase->targetFileName = "InvalidcRLIssuerTest32EE.crt";
        testCase->altTestName = "4.14.32";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA6");
        testCase->targetFileName = "ValidcRLIssuerTest33EE.crt";
        testCase->altTestName = "4.14.33";
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA5");
        testCase->targetFileName = "InvalidcRLIssuerTest34EE.crt";
        testCase->altTestName = "4.14.34";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("indirectCRLCA5");
        testCase->targetFileName = "InvalidcRLIssuerTest35EE.crt";
        testCase->altTestName = "4.14.35";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.14"].push_back(testCase);
        g_pkitsSettingsMap["4.14"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.15 - delta CRLs - 10 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLIndicatorNoBaseCA");
        testCase->targetFileName = "InvaliddeltaCRLIndicatorNoBaseTest1EE.crt";
        testCase->altTestName = "4.15.1";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA1");
        testCase->targetFileName = "ValiddeltaCRLTest2EE.crt";
        testCase->altTestName = "4.15.2";
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA1");
        testCase->targetFileName = "InvaliddeltaCRLTest3EE.crt";
        testCase->altTestName = "4.15.3";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA1");
        testCase->targetFileName = "InvaliddeltaCRLTest4EE.crt";
        testCase->altTestName = "4.15.4";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA1");
        testCase->targetFileName = "ValiddeltaCRLTest5EE.crt";
        testCase->altTestName = "4.15.5";
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA1");
        testCase->targetFileName = "InvaliddeltaCRLTest6EE.crt";
        testCase->altTestName = "4.15.6";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA1");
        testCase->targetFileName = "ValiddeltaCRLTest7EE.crt";
        testCase->altTestName = "4.15.7";
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA2");
        testCase->targetFileName = "ValiddeltaCRLTest8EE.crt";
        testCase->altTestName = "4.15.8";
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA2");
        testCase->targetFileName = "InvaliddeltaCRLTest9EE.crt";
        testCase->altTestName = "4.15.9";
        testCase->errorCode = CERTIFICATE_REVOKED;
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->intermediateCaNames.push_back("deltaCRLCA3");
        testCase->targetFileName = "InvaliddeltaCRLTest10EE.crt";
        testCase->altTestName = "4.15.10";
        testCase->errorCode = REVOCATION_STATUS_NOT_DETERMINED;
        g_pkitsDataMap["4.15"].push_back(testCase);
        g_pkitsSettingsMap["4.15"].push_back("DefaultSettings");
    }
    
    //-----------------------------------------------------------------------------
    //Section 4.16 - private certificate extensions - 2 tests
    //-----------------------------------------------------------------------------
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->targetFileName = "ValidUnknownNotCriticalCertificateExtensionTest1EE.crt";
        g_pkitsDataMap["4.16"].push_back(testCase);
        g_pkitsSettingsMap["4.16"].push_back("DefaultSettings");
    }
    {
        PkitsTestCasePtr testCase(new PkitsTestCase);
        testCase->targetFileName = "InvalidUnknownCriticalCertificateExtensionTest2EE.crt";
        testCase->errorCode = UNPROCESSED_CRITICAL_EXTENSION;
        g_pkitsDataMap["4.16"].push_back(testCase);
        g_pkitsSettingsMap["4.16"].push_back("DefaultSettings");
    }
    
}

void output_csv()
{
    for(int ii = 0; ii < 1; ++ii)
    {
        //iterate over the test case sections
        std::map<std::string, std::vector<PkitsTestCasePtr> >::iterator mPos;
        std::map<std::string, std::vector<PkitsTestCasePtr> >::iterator mEnd = g_pkitsDataMap.end();
        for(mPos = g_pkitsDataMap.begin(); mEnd != mPos; ++mPos)
        {
            //iterate over the test cases within each secction
            std::string section = (*mPos).first;
            std::vector<PkitsTestCasePtr>::iterator pos;
            std::vector<PkitsTestCasePtr>::iterator end = g_pkitsDataMap[section].end();
            for(pos = g_pkitsDataMap[section].begin(); pos != end; ++pos)
            {
                int testIndex = distance(g_pkitsDataMap[section].begin(), pos);
                
                std::ostringstream testName;
                if(!(*pos)->altTestName)
                    testName << section.c_str() << "." << testIndex+1;
                else
                    testName << (*pos)->altTestName;
                
                testName << "," << (*pos)->targetFileName;
                testName << "," << g_pkitsSettingsMap[section][testIndex];
                testName << "," << (*pos)->errorCode;
                std::cout << testName.str().c_str() << std::endl;
            }
        }
    }
}

char* g_pdtsFilenames[] = {
    (char*)"RudimentaryHTTPURIPathDiscoveryTest2EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest4EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest7EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest8EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest13EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest14EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest15EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest16EE.crt",
    (char*)"BasicHTTPURIPathDiscoveryTest2EE.crt",
    (char*)"BasicHTTPURIPathDiscoveryTest4EE.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU1EE1.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU1EE2.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU1EE3.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU1EE4.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU1EE5.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE1.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE2.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE3.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE4.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE5.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU3EE1.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU3EE2.crt",
    NULL
};

char* g_pdtsFilenamesFail[] = {
    (char*)"RudimentaryHTTPURIPathDiscoveryTest8EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest14EE.crt",
    (char*)"RudimentaryHTTPURIPathDiscoveryTest16EE.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU1EE4.crt",
    (char*)"BasicHTTPURIPathDiscoveryOU1EE5.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE2.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE4.crt",
    (char*)"BasicHTTPURIPathDiscoveryOrg2EE5.crt",
    NULL
};

bool IsPdts(const std::string& f)
{
    for(int ii = 0; NULL != g_pdtsFilenames[ii]; ++ ii)
    {
        if(f == g_pdtsFilenames[ii])
            return true;
    }
    return false;
}
bool IsPdtsFailure(const std::string& f)
{
    for(int ii = 0; NULL != g_pdtsFilenamesFail[ii]; ++ ii)
    {
        if(f == g_pdtsFilenamesFail[ii])
            return true;
    }
    return false;
}


const std::string g_clientName = "java -jar vss2.jar";

enum script_type {
    DEFAULT_WITH_TA = 0,
    DEFAULT_OMIT_TA,
    NON_DEFAULT
};

const std::string g_test_policy_1 = "2.16.840.1.101.3.2.1.48.1";
const std::string g_test_policy_2 = "2.16.840.1.101.3.2.1.48.2";
const std::string g_test_policy_3 = "2.16.840.1.101.3.2.1.48.3";
const std::string g_test_policy_4 = "2.16.840.1.101.3.2.1.48.4";
const std::string g_test_policy_5 = "2.16.840.1.101.3.2.1.48.5";
const std::string g_test_policy_6 = "2.16.840.1.101.3.2.1.48.6";

const std::string g_scvp_pkits_2048_def = "1.3.6.1.4.1.37623.10.1.1.0";
const std::string g_scvp_pkits_2048_1 = "1.3.6.1.4.1.37623.10.1.1.1";
const std::string g_scvp_pkits_2048_2 = "1.3.6.1.4.1.37623.10.1.1.2";
const std::string g_scvp_pkits_2048_3 = "1.3.6.1.4.1.37623.10.1.1.3";
const std::string g_scvp_pkits_2048_4 = "1.3.6.1.4.1.37623.10.1.1.4";
const std::string g_scvp_pkits_2048_5 = "1.3.6.1.4.1.37623.10.1.1.5";
const std::string g_scvp_pkits_2048_6 = "1.3.6.1.4.1.37623.10.1.1.6";
const std::string g_scvp_pkits_2048_7 = "1.3.6.1.4.1.37623.10.1.1.7";
const std::string g_scvp_pkits_2048_8 = "1.3.6.1.4.1.37623.10.1.1.8";
const std::string g_scvp_pkits_2048_9 = "1.3.6.1.4.1.37623.10.1.1.9";
const std::string g_scvp_pkits_2048_10 = "1.3.6.1.4.1.37623.10.1.1.10";

const std::string g_scvp_pkits_4096_def = "1.3.6.1.4.1.37623.10.1.2.0";
const std::string g_scvp_pkits_4096_1 = "1.3.6.1.4.1.37623.10.1.2.1";
const std::string g_scvp_pkits_4096_2 = "1.3.6.1.4.1.37623.10.1.2.2";
const std::string g_scvp_pkits_4096_3 = "1.3.6.1.4.1.37623.10.1.2.3";
const std::string g_scvp_pkits_4096_4 = "1.3.6.1.4.1.37623.10.1.2.4";
const std::string g_scvp_pkits_4096_5 = "1.3.6.1.4.1.37623.10.1.2.5";
const std::string g_scvp_pkits_4096_6 = "1.3.6.1.4.1.37623.10.1.2.6";
const std::string g_scvp_pkits_4096_7 = "1.3.6.1.4.1.37623.10.1.2.7";
const std::string g_scvp_pkits_4096_8 = "1.3.6.1.4.1.37623.10.1.2.8";
const std::string g_scvp_pkits_4096_9 = "1.3.6.1.4.1.37623.10.1.2.9";
const std::string g_scvp_pkits_4096_10 = "1.3.6.1.4.1.37623.10.1.2.10";


const std::string g_scvp_pkits_p256_def = "1.3.6.1.4.1.37623.10.1.3.0";
const std::string g_scvp_pkits_p256_1 = "1.3.6.1.4.1.37623.10.1.3.1";
const std::string g_scvp_pkits_p256_2 = "1.3.6.1.4.1.37623.10.1.3.2";
const std::string g_scvp_pkits_p256_3 = "1.3.6.1.4.1.37623.10.1.3.3";
const std::string g_scvp_pkits_p256_4 = "1.3.6.1.4.1.37623.10.1.3.4";
const std::string g_scvp_pkits_p256_5 = "1.3.6.1.4.1.37623.10.1.3.5";
const std::string g_scvp_pkits_p256_6 = "1.3.6.1.4.1.37623.10.1.3.6";
const std::string g_scvp_pkits_p256_7 = "1.3.6.1.4.1.37623.10.1.3.7";
const std::string g_scvp_pkits_p256_8 = "1.3.6.1.4.1.37623.10.1.3.8";
const std::string g_scvp_pkits_p256_9 = "1.3.6.1.4.1.37623.10.1.3.9";
const std::string g_scvp_pkits_p256_10 = "1.3.6.1.4.1.37623.10.1.3.10";

const std::string g_scvp_pkits_p384_def = "1.3.6.1.4.1.37623.10.1.4.0";
const std::string g_scvp_pkits_p384_1 = "1.3.6.1.4.1.37623.10.1.4.1";
const std::string g_scvp_pkits_p384_2 = "1.3.6.1.4.1.37623.10.1.4.2";
const std::string g_scvp_pkits_p384_3 = "1.3.6.1.4.1.37623.10.1.4.3";
const std::string g_scvp_pkits_p384_4 = "1.3.6.1.4.1.37623.10.1.4.4";
const std::string g_scvp_pkits_p384_5 = "1.3.6.1.4.1.37623.10.1.4.5";
const std::string g_scvp_pkits_p384_6 = "1.3.6.1.4.1.37623.10.1.4.6";
const std::string g_scvp_pkits_p384_7 = "1.3.6.1.4.1.37623.10.1.4.7";
const std::string g_scvp_pkits_p384_8 = "1.3.6.1.4.1.37623.10.1.4.8";
const std::string g_scvp_pkits_p384_9 = "1.3.6.1.4.1.37623.10.1.4.9";
const std::string g_scvp_pkits_p384_10 = "1.3.6.1.4.1.37623.10.1.4.10";

void AppendPathSettings(const std::string& settingsName, std::ostringstream& output)
{
    if("DefaultSettings" == settingsName)
    {
        
    }
    else if("Settings1" == settingsName)
    {
        output << "--requireExplicitPolicy true" << " ";
    }
    else if("Settings2" == settingsName)
    {
        output << "--requireExplicitPolicy true" << " ";
        output << "--certificate_policy " << g_test_policy_1.c_str()  << " ";
    }
    else if("Settings3" == settingsName)
    {
        output << "--requireExplicitPolicy true" << " ";
        output << "--certificate_policy " << g_test_policy_2.c_str()  << " ";
    }
    else if("Settings4" == settingsName)
    {
        output << "--requireExplicitPolicy true" << " ";
        output << "--certificate_policy " << g_test_policy_1.c_str()  << " " << g_test_policy_2.c_str()  << " ";
    }
    else if("Settings5" == settingsName)
    {
        output << "--certificate_policy " << g_test_policy_1.c_str()  << " ";
    }
    else if("Settings6" == settingsName)
    {
        output << "--certificate_policy " << g_test_policy_2.c_str()  << " ";
    }
    else if("Settings7" == settingsName)
    {
        output << "--certificate_policy " << g_test_policy_3.c_str()  << " ";
    }
    else if("Settings8" == settingsName)
    {
        output << "--inhibitPolicyMapping true" << " ";
    }
    else if("Settings9" == settingsName)
    {
        output << "--certificate_policy " << g_test_policy_6.c_str()  << " ";
    }
    else if("Settings10" == settingsName)
    {
        output << "--inhibitAnyPolicy true" << " ";
    }
}

std::string GetNonDefault(enum PKITS_Edition pe, const std::string& settingsName)
{
    if(PKITS_2048 == pe)
    {
        if("DefaultSettings" == settingsName)
        {
            return g_scvp_pkits_2048_def;
        }
        else if("Settings1" == settingsName)
        {
            return g_scvp_pkits_2048_1;
        }
        else if("Settings2" == settingsName)
        {
            return g_scvp_pkits_2048_2;
        }
        else if("Settings3" == settingsName)
        {
            return g_scvp_pkits_2048_3;
        }
        else if("Settings4" == settingsName)
        {
            return g_scvp_pkits_2048_4;
        }
        else if("Settings5" == settingsName)
        {
            return g_scvp_pkits_2048_5;
        }
        else if("Settings6" == settingsName)
        {
            return g_scvp_pkits_2048_6;
        }
        else if("Settings7" == settingsName)
        {
            return g_scvp_pkits_2048_7;
        }
        else if("Settings8" == settingsName)
        {
            return g_scvp_pkits_2048_8;
        }
        else if("Settings9" == settingsName)
        {
            return g_scvp_pkits_2048_9;
        }
        else if("Settings10" == settingsName)
        {
            return g_scvp_pkits_2048_10;
        }
    }
    else if(PKITS_4096 == pe)
    {
        if("DefaultSettings" == settingsName)
        {
            return g_scvp_pkits_4096_def;
        }
        else if("Settings1" == settingsName)
        {
            return g_scvp_pkits_4096_1;
        }
        else if("Settings2" == settingsName)
        {
            return g_scvp_pkits_4096_2;
        }
        else if("Settings3" == settingsName)
        {
            return g_scvp_pkits_4096_3;
        }
        else if("Settings4" == settingsName)
        {
            return g_scvp_pkits_4096_4;
        }
        else if("Settings5" == settingsName)
        {
            return g_scvp_pkits_4096_5;
        }
        else if("Settings6" == settingsName)
        {
            return g_scvp_pkits_4096_6;
        }
        else if("Settings7" == settingsName)
        {
            return g_scvp_pkits_4096_7;
        }
        else if("Settings8" == settingsName)
        {
            return g_scvp_pkits_4096_8;
        }
        else if("Settings9" == settingsName)
        {
            return g_scvp_pkits_4096_9;
        }
        else if("Settings10" == settingsName)
        {
            return g_scvp_pkits_4096_10;
        }
    }
    else if(PKITS_P256 == pe)
    {
        if("DefaultSettings" == settingsName)
        {
            return g_scvp_pkits_p256_def;
        }
        else if("Settings1" == settingsName)
        {
            return g_scvp_pkits_p256_1;
        }
        else if("Settings2" == settingsName)
        {
            return g_scvp_pkits_p256_2;
        }
        else if("Settings3" == settingsName)
        {
            return g_scvp_pkits_p256_3;
        }
        else if("Settings4" == settingsName)
        {
            return g_scvp_pkits_p256_4;
        }
        else if("Settings5" == settingsName)
        {
            return g_scvp_pkits_p256_5;
        }
        else if("Settings6" == settingsName)
        {
            return g_scvp_pkits_p256_6;
        }
        else if("Settings7" == settingsName)
        {
            return g_scvp_pkits_p256_7;
        }
        else if("Settings8" == settingsName)
        {
            return g_scvp_pkits_p256_8;
        }
        else if("Settings9" == settingsName)
        {
            return g_scvp_pkits_p256_9;
        }
        else if("Settings10" == settingsName)
        {
            return g_scvp_pkits_p256_10;
        }
    }
    else if(PKITS_P384 == pe)
    {
        if("DefaultSettings" == settingsName)
        {
            return g_scvp_pkits_p384_def;
        }
        else if("Settings1" == settingsName)
        {
            return g_scvp_pkits_p384_1;
        }
        else if("Settings2" == settingsName)
        {
            return g_scvp_pkits_p384_2;
        }
        else if("Settings3" == settingsName)
        {
            return g_scvp_pkits_p384_3;
        }
        else if("Settings4" == settingsName)
        {
            return g_scvp_pkits_p384_4;
        }
        else if("Settings5" == settingsName)
        {
            return g_scvp_pkits_p384_5;
        }
        else if("Settings6" == settingsName)
        {
            return g_scvp_pkits_p384_6;
        }
        else if("Settings7" == settingsName)
        {
            return g_scvp_pkits_p384_7;
        }
        else if("Settings8" == settingsName)
        {
            return g_scvp_pkits_p384_8;
        }
        else if("Settings9" == settingsName)
        {
            return g_scvp_pkits_p384_9;
        }
        else if("Settings10" == settingsName)
        {
            return g_scvp_pkits_p384_10;
        }
    }
    return "unknown";
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
     -u SCVP_URL, --scvp_url SCVP_URL
        URL of SCVP to query. Example: https://vssapi.example.com/vss/pkix.
     --scvp_profile {lightweight,long-term-record,batch}
        Name of SCVP profile. (default: lightweight)
     -x {true,false}, --expectSuccess {true,false}
        Boolean value indicating whether success is expected. Applies to either --target_cert or all certs in --batch_folder (default: true)
     -l LOGGING_CONF, --logging_conf LOGGING_CONF
        Full path and filename of log4j configuration file.
     -n TEST_CASE_NAME, --test_case_name TEST_CASE_NAME
        Friendly name of test case (mostly for logging purposes).
 
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
 The below snip is from section 4.1 "Lightweight" SCVP Client Request from treas_scvp_profile_v1.3.pdf.
 
 1. CVRequest MUST contain cvRequestVersion.
    1. The value of cvRequestVersion MUST be set to 1.
 2. queriedCerts MUST contain exactly one CertReferences item.
    1. CertReferences MUST contain exactly one pkcRefs item.
        1.pkcRefs MUST contain exactly one PKCReference item.
            1. PKCReference MUST include the certificate in the cert item.
 3. checks MUST contain exactly one CertChecks item.
    1. CertChecks MUST include the OID 1.3.6.1.5.5.7.17.3 (id-stc-build-status-checked-pkc-path)
 4. wantBack MAY include one or more WantBack OIDs.
 5. validationAlg SHOULD contain exactly one ValidationAlg.
    1. ValidationAlg MUST include valAlgId.
        1.The value of valAlgId MUST be set to the id-svp-basicValAlg OID.
 6. responseFlags SHOULD include the following ResponseFlags:
    1. fullRequestInResponse
        1.The flag value MUST be set to FALSE.
    2. responseValidationPolByRef
        1.The flag value MUST be set to TRUE.
    3. protectResponse
        1.The flag MUST be set to TRUE.
    4. cachedResponse
        1.The flag MUST be set to TRUE.
 7. revInfos MUST be omitted.
 8. producedAt MUST be omitted.
 9. requestNonce MUST be omitted.
 10. ValidationPolicy MUST include exactly one ValidationPolRef.
    1. The valPolId MUST specify one of the policy OIDs defined in this profile, and valPolParams MUST be null.
 11. requestorText MUST be omitted.
 */
void output_script_lightweight_pkits(const std::string& logging_conf, const std::string& output_folder, const std::string& pkits_folder, enum PKITS_Edition pe, std::vector<std::string>& wantBacks)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        if(PKITS_2048 == pe)
            filename << "PKITSv2_2048_";
        else if(PKITS_4096 == pe)
            filename << "PKITSv2_4096_";
        else if(PKITS_P256 == pe)
            filename << "PKITSv2_P256_";
        else if(PKITS_P384 == pe)
            filename << "PKITSv2_P384_";
        
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "DEFAULT_WITH_TA";
            }
            else
            {
                filename << "DEFAULT_OMIT_TA";
            }
        }
        else
        {
            filename << "NON_DEFAULT";
        }
        filename << "_lightweight.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        for(int ii = 0; ii < 1; ++ii)
        {
            //iterate over the test case sections
            std::map<std::string, std::vector<PkitsTestCasePtr> >::iterator mPos;
            std::map<std::string, std::vector<PkitsTestCasePtr> >::iterator mEnd = g_pkitsDataMap.end();
            for(mPos = g_pkitsDataMap.begin(); mEnd != mPos; ++mPos)
            {
                //iterate over the test cases within each secction
                std::string section = (*mPos).first;
                std::vector<PkitsTestCasePtr>::iterator pos;
                std::vector<PkitsTestCasePtr>::iterator end = g_pkitsDataMap[section].end();
                for(pos = g_pkitsDataMap[section].begin(); pos != end; ++pos)
                {
                    int testIndex = distance(g_pkitsDataMap[section].begin(), pos);

                    boost::filesystem::path ta = pkits_folder;
                    ta /= (*pos)->taCertFileName;
                    
                    std::ostringstream output;
                    
                    boost::filesystem::path target = pkits_folder;
                    target /= (*pos)->targetFileName;
                    
                    std::ostringstream testName;
                    if(!(*pos)->altTestName)
                        testName << section.c_str() << "." << testIndex+1;
                    else
                        testName << (*pos)->altTestName;
                    
                    output << g_clientName << " ";
                    output << "--scvp_profile lightweight" << " ";
                    if(!logging_conf.empty())
                        output << "-l " << logging_conf.c_str() << " ";
                    output << "-n " << testName.str().c_str() << " ";
                    output << "-c " << target.string().c_str() << " ";
                    if(0 != (*pos)->errorCode)
                    {
                        output << "-x false" << " ";
                    }
                    
                    if(!wantBacks.empty())
                    {
                        output << "--wantBacks ";
                        std::vector<std::string>::iterator pos;
                        std::vector<std::string>::iterator end = wantBacks.end();
                        for(pos = wantBacks.begin(); pos != end; ++pos)
                        {
                            output << (*pos) << " ";
                        }
                    }
                    
                    if(NON_DEFAULT == zz)
                    {
                        //use appropriate non-default validation policy OID
                        std::string nonDefaultPolicy = GetNonDefault(pe, g_pkitsSettingsMap[section][testIndex]);
                        output << "-v " << nonDefaultPolicy.c_str() << " ";
                    }
                    else
                    {
                        //pass in the appropriate path settings values and, optionally, TA
                        if(DEFAULT_WITH_TA == zz)
                        {
                            output << "-t " << ta.string().c_str() << " ";
                        }
                        AppendPathSettings(g_pkitsSettingsMap[section][testIndex], output);
                    }

                    std::cout << output.str().c_str() << std::endl;
                    scriptfile << output.str().c_str() << std::endl;
                }
            }
        }
    }
}

/*
 The below snip is from section 4.2 "Long Term Record" SCVP Client Request from treas_scvp_profile_v1.3.pdf.
 
    1. CVRequest MUST contain cvRequestVersion.
        1. The value of cvRequestVersion MUST be set to 1.
    2. queriedCerts MAY contain exactly one CertReferences item.
        1. CertReferences MUST contain exactly one pkcRefs item.
            1.pkcRefs MUST contain exactly one PKCReference item.
                1. PKCReference MUST include the certificate in the cert item.
    3. checks MUST contain exactly one CertChecks item.
        1. CertChecks MUST include the OID 1.3.6.1.5.5.7.17.3 (id-stc-build-status-checked-pkc-path)
    4. wantBack MAY include one or more WantBack OIDs.
    5. validationAlg SHOULD contain exactly one ValidationAlg.
        1. ValidationAlg MUST include valAlgId.
            1.The value of valAlgId MUST be set to the id-svp-basicValAlg OID.
    6. responseFlags SHOULD include the following ResponseFlags:
        1. fullRequestInResponse
            1.The flag value MUST be set to TRUE.
        2. responseValidationPolByRef
            1.The flag value MUST be set to FALSE.
        3. protectResponse
            1.The flag MUST be set to TRUE.
        4. cachedResponse
            1.The flag value MUST be set to FALSE.
    7. revInfos MUST be omitted.
    8. producedAt MUST be omitted.
    9. requestNonce SHOULD be included.
        1. The requestNonce value SHOULD be at least 16 bytes in length, and MUST NOT exceed 64 bytes.
    10. ValidationPolicy MUST include exactly one ValidationPolRef.
        1. The valPolId MUST specify one of the policy OIDs defined in this profile, and valPolParams MUST be null.
    11. requestorText MUST be included.
        1. The requestorText item MUST conform to the formatting requirements in this profile. (see requestorText Format Requirements)
*/
void output_script_longterm_pkits(const std::string& logging_conf, const std::string& output_folder, const std::string& pkits_folder, enum PKITS_Edition pe, std::vector<std::string>& wantBacks)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        if(PKITS_2048 == pe)
            filename << "PKITSv2_2048_";
        else if(PKITS_4096 == pe)
            filename << "PKITSv2_4096_";
        else if(PKITS_P256 == pe)
            filename << "PKITSv2_P256_";
        else if(PKITS_P384 == pe)
            filename << "PKITSv2_P384_";
        
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "DEFAULT_WITH_TA";
            }
            else
            {
                filename << "DEFAULT_OMIT_TA";
            }
        }
        else
        {
            filename << "NON_DEFAULT";
        }
        filename << "_longterm.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        for(int ii = 0; ii < 1; ++ii)
        {
            //iterate over the test case sections
            std::map<std::string, std::vector<PkitsTestCasePtr> >::iterator mPos;
            std::map<std::string, std::vector<PkitsTestCasePtr> >::iterator mEnd = g_pkitsDataMap.end();
            for(mPos = g_pkitsDataMap.begin(); mEnd != mPos; ++mPos)
            {
                //iterate over the test cases within each secction
                std::string section = (*mPos).first;
                std::vector<PkitsTestCasePtr>::iterator pos;
                std::vector<PkitsTestCasePtr>::iterator end = g_pkitsDataMap[section].end();
                for(pos = g_pkitsDataMap[section].begin(); pos != end; ++pos)
                {
                    int testIndex = distance(g_pkitsDataMap[section].begin(), pos);
                    
                    boost::filesystem::path ta = pkits_folder;
                    ta /= (*pos)->taCertFileName;
                    
                    std::ostringstream output;
                    
                    boost::filesystem::path target = pkits_folder;
                    target /= (*pos)->targetFileName;
                    
                    std::ostringstream testName;
                    if(!(*pos)->altTestName)
                        testName << section.c_str() << "." << testIndex+1;
                    else
                        testName << (*pos)->altTestName;
                    
                    output << g_clientName << " ";
                    output << "--scvp_profile long-term-record" << " ";
                    if(!logging_conf.empty())
                        output << "-l " << logging_conf.c_str() << " ";
                    output << "-n " << testName.str().c_str() << " ";
                    output << "-c " << target.string().c_str() << " ";
                    if(0 != (*pos)->errorCode)
                    {
                        output << "-x false" << " ";
                    }

                    if(!wantBacks.empty())
                    {
                        output << "--wantBacks ";
                        std::vector<std::string>::iterator pos;
                        std::vector<std::string>::iterator end = wantBacks.end();
                        for(pos = wantBacks.begin(); pos != end; ++pos)
                        {
                            output << (*pos) << " ";
                        }
                    }
                    
                    if(NON_DEFAULT == zz)
                    {
                        //use appropriate non-default validation policy OID
                        std::string nonDefaultPolicy = GetNonDefault(pe, g_pkitsSettingsMap[section][testIndex]);
                        output << "-v " << nonDefaultPolicy.c_str() << " ";
                    }
                    else
                    {
                        //pass in the appropriate path settings values and, optionally, TA
                        if(DEFAULT_WITH_TA == zz)
                        {
                            output << "-t " << ta.string().c_str() << " ";
                        }
                        AppendPathSettings(g_pkitsSettingsMap[section][testIndex], output);
                    }
                    
                    std::cout << output.str().c_str() << std::endl;
                    scriptfile << output.str().c_str() << std::endl;
                }
            }
        }
    }
}

/*
     1. CVRequest MUST contain cvRequestVersion.
        1. The value of cvRequestVersion MUST be set to 1.
     2. queriedCerts MUST contain exactly one CertReferences item.
        1. CertReferences MUST contain exactly one pkcRefs item.
            1.pkcRefs MAY contain one or more PKCReference item(s), not to exceed 256.
                1. PKCReference MUST include the certificate in the cert item.
     3. checks MUST contain exactly one CertChecks item.
        1. CertChecks MUST include the OID 1.3.6.1.5.5.7.17.3 (id-stc-build-status-checked-pkc-path)
     4. wantBack MUST NOT include WantBack OIDs.
     5. validationAlg SHOULD contain exactly one ValidationAlg.
         1. ValidationAlg MUST include valAlgId.
            1.The value of valAlgId MUST be set to the id-svp-basicValAlg OID.
     6. responseFlags SHOULD include the following ResponseFlags:
         1. fullRequestInResponse
            1.The flag value MUST be set to FALSE.
         2. responseValidationPolByRef
            1.The flag value MUST be set to TRUE.
         3. protectResponse
            1.The flag MUST be set to TRUE.
         4. cachedResponse
            1.The flag MUST be set to TRUE.
     7. revInfos MUST be omitted.
     8. producedAt MUST be omitted.
     9. requestNonce MUST be omitted.
     10. ValidationPolicy MUST include exactly one ValidationPolRef.
        1. The valPolId MUST specify one of the policy OIDs defined in this profile, and valPolParams MUST be null.
     11. requestorText MUST be omitted.
 */
void output_script_batch_pkits(const std::string& logging_conf, const std::string& output_folder, const std::string& pkits_folder, enum PKITS_Edition pe, std::vector<std::string>& wantBacks)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        if(PKITS_2048 == pe)
            filename << "PKITSv2_2048_";
        else if(PKITS_4096 == pe)
            filename << "PKITSv2_4096_";
        else if(PKITS_P256 == pe)
            filename << "PKITSv2_P256_";
        else if(PKITS_P384 == pe)
            filename << "PKITSv2_P384_";
        
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "DEFAULT_WITH_TA";
            }
            else
            {
                filename << "DEFAULT_OMIT_TA";
            }
        }
        else
        {
            filename << "NON_DEFAULT";
        }
        filename << "_batch.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        for(int ii = 0; ii < 33; ++ii)
        {
            std::string settingsName;
            std::ostringstream testName;
            boost::filesystem::path target_folder = pkits_folder;
            //target_folder /= "Renamed";
            switch(ii)
            {
                case 0:
                    settingsName = "DefaultSettings";
                    target_folder /= "default";
                    break;
                case 1:
                    settingsName = "Settings1";
                    target_folder /= "1";
                    break;
                case 2:
                    settingsName = "Settings2";
                    target_folder /= "2";
                    break;
                case 3:
                    settingsName = "Settings3";
                    target_folder /= "3";
                    break;
                case 4:
                    settingsName = "Settings4";
                    target_folder /= "4";
                    break;
                case 5:
                    settingsName = "Settings5";
                    target_folder /= "5";
                    break;
                case 6:
                    settingsName = "Settings6";
                    target_folder /= "6";
                    break;
                case 7:
                    settingsName = "Settings7";
                    target_folder /= "7";
                    break;
                case 8:
                    settingsName = "Settings8";
                    target_folder /= "8";
                    break;
                case 9:
                    settingsName = "Settings9";
                    target_folder /= "9";
                    break;
                case 10:
                    settingsName = "Settings10";
                    target_folder /= "10";
                    break;
                case 11:
                    settingsName = "DefaultSettings";
                    target_folder /= "default_good";
                    break;
                case 12:
                    settingsName = "Settings1";
                    target_folder /= "1_good";
                    break;
                case 13:
                    settingsName = "Settings2";
                    target_folder /= "2_good";
                    break;
                case 14:
                    settingsName = "Settings3";
                    target_folder /= "3_good";
                    continue;
                    break;
                case 15:
                    settingsName = "Settings4";
                    target_folder /= "4_good";
                    break;
                case 16:
                    settingsName = "Settings5";
                    target_folder /= "5_good";
                    break;
                case 17:
                    settingsName = "Settings6";
                    target_folder /= "6_good";
                    break;
                case 18:
                    settingsName = "Settings7";
                    target_folder /= "7_good";
                    break;
                case 19:
                    settingsName = "Settings8";
                    target_folder /= "8_good";
                    continue;
                    break;
                case 20:
                    settingsName = "Settings9";
                    target_folder /= "9_good";
                    continue;
                    break;
                case 21:
                    settingsName = "Settings10";
                    target_folder /= "10_good";
                    continue;
                    break;
                case 22:
                    settingsName = "DefaultSettings";
                    target_folder /= "default_bad";
                    break;
                case 23:
                    settingsName = "Settings1";
                    target_folder /= "1_bad";
                    break;
                case 24:
                    settingsName = "Settings2";
                    target_folder /= "2_bad";
                    continue;
                    break;
                case 25:
                    settingsName = "Settings3";
                    target_folder /= "3_bad";
                    break;
                case 26:
                    settingsName = "Settings4";
                    target_folder /= "4_bad";
                    break;
                case 27:
                    settingsName = "Settings5";
                    target_folder /= "5_bad";
                    break;
                case 28:
                    settingsName = "Settings6";
                    target_folder /= "6_bad";
                    break;
                case 29:
                    settingsName = "Settings7";
                    target_folder /= "7_bad";
                    continue;
                    break;
                case 30:
                    settingsName = "Settings8";
                    target_folder /= "8_bad";
                    break;
                case 31:
                    settingsName = "Settings9";
                    target_folder /= "9_bad";
                    break;
                case 32:
                    settingsName = "Settings10";
                    target_folder /= "10_bad";
                    break;
            };
            
            boost::filesystem::path ta = pkits_folder;
            ta /= "TrustAnchorRootCertificate.crt";
            
            std::ostringstream output;
           
            output << g_clientName << " ";
            output << "--scvp_profile batch" << " ";
            if(!logging_conf.empty())
                output << "-l " << logging_conf.c_str() << " ";
            //output << "-n " << testName.str().c_str() << " ";
            if(ii < 11)
                output << "--batch_folder " << target_folder.string().c_str() << " ";
            else if(ii <= 22)
                output << "--batch_folder_success " << target_folder.string().c_str() << " ";
            else
                output << "--batch_folder_failure " << target_folder.string().c_str() << " ";

            if(NON_DEFAULT == zz)
            {
                //use appropriate non-default validation policy OID
                std::string nonDefaultPolicy = GetNonDefault(pe, settingsName);
                output << "-v " << nonDefaultPolicy.c_str() << " ";
            }
            else
            {
                //pass in the appropriate path settings values and, optionally, TA
                if(DEFAULT_WITH_TA == zz)
                {
                    output << "-t " << ta.string().c_str() << " ";
                }
                AppendPathSettings(settingsName, output);
            }
            
            std::cout << output.str().c_str() << std::endl;
            scriptfile << output.str().c_str() << std::endl;
        }
    }
}

void output_script_lightweight_pdts(const std::string& logging_conf, const std::string& output_folder, const std::string& pdts_folder, std::vector<std::string>& wantBacks)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "PDTS_DEFAULT_WITH_TA";
            }
            else
            {
                filename << "PDTS_DEFAULT_OMIT_TA";
            }
        }
        else
        {
            filename << "PDTS_NON_DEFAULT";
        }
        filename << "_lightweight.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        try {
            if(fs::exists( pdts_folder ) )
            {
                fs::directory_iterator end_itr;
                for (fs::directory_iterator itr( pdts_folder ); itr != end_itr; ++itr )
                {
                    if(fs::is_directory(itr->status()))
                    {
                        //not recursing for these utility
                    }
                    else
                    {
                        static boost::regex crlFilter;
                        static const char * crlPattern = "^.*\\.(der|crt|cer|pem)$";
                        static bool crlFilterInit = false;
                        if(!crlFilterInit)
                        {
                            try
                            {
                                crlFilter.assign(crlPattern,boost::regex_constants::perl);
                                crlFilterInit = true;
                            }
                            catch(std::exception& se)
                            {
                                std::ostringstream oss;
                                oss << "Failed to initialize regular expression filter";
                                if(se.what())
                                    oss << ": " << se.what();
                                std::cerr << (oss.str().c_str());
                            }
                        }
                        
                        bool processFile = false;
                        if(crlFilterInit)
                        {
                            boost::smatch what;
                            if( boost::regex_search( itr->path().leaf().string(), what, crlFilter ) )
                            {
                                //the filename matches the filter
                                processFile = true;
                            }
                        }
                        else
                        {
                            //the filter could not be prepared
                            processFile = true;
                        }
                        
                        if(processFile && IsPdts(itr->path().leaf().string()))
                        {
                            boost::filesystem::path ta = pdts_folder;
                            ta /= "BasicHTTPURITrustAnchorRootCert.crt";
                            
                            std::ostringstream output;
                            
                            boost::filesystem::path target = itr->path();
                            
                            std::ostringstream testName;
                            testName << itr->path().leaf();
                            
                            output << g_clientName << " ";
                            output << "--scvp_profile lightweight" << " ";
                            if(!logging_conf.empty())
                                output << "-l " << logging_conf.c_str() << " ";
                            output << "-n " << testName.str().c_str() << " ";
                            output << "-c " << target.string().c_str() << " ";
                            if(IsPdtsFailure(itr->path().leaf().string()))
                            {
                                output << "-x false" << " ";
                            }
                            
                            if(!wantBacks.empty())
                            {
                                output << "--wantBacks ";
                                std::vector<std::string>::iterator pos;
                                std::vector<std::string>::iterator end = wantBacks.end();
                                for(pos = wantBacks.begin(); pos != end; ++pos)
                                {
                                    output << (*pos) << " ";
                                }
                            }
                            
                            if(NON_DEFAULT == zz)
                            {
                                //use appropriate non-default validation policy OID
                                std::string nonDefaultPolicy = "1.3.6.1.4.1.37623.10.1.5.0";
                                output << "-v " << nonDefaultPolicy.c_str() << " ";
                            }
                            else
                            {
                                //pass in the appropriate path settings values and, optionally, TA
                                if(DEFAULT_WITH_TA == zz)
                                {
                                    output << "-t " << ta.string().c_str() << " ";
                                }
                                AppendPathSettings("DefaultPathSettings", output);
                            }
                            
                            std::cout << output.str().c_str() << std::endl;
                            scriptfile << output.str().c_str() << std::endl;
                        }
                    }
                    
                }//end directory iterator
            }// end if path exists
            else
            {
                std::ostringstream oss;
                oss << "Path to PDTS collection does not exist: " << pdts_folder.c_str();
                std::cerr << (oss.str().c_str());
            }
        } catch(fs::filesystem_error & e) {
            std::cerr << e.what();
        }
    }
}
void output_script_longterm_pdts(const std::string& logging_conf, const std::string& output_folder, const std::string& pdts_folder, std::vector<std::string>& wantBacks)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "PDTS_DEFAULT_WITH_TA";
            }
            else
            {
                filename << "PDTS_DEFAULT_OMIT_TA";
            }
        }
        else
        {
            filename << "PDTS_NON_DEFAULT";
        }
        filename << "_longterm.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        try {
            if(fs::exists( pdts_folder ) )
            {
                fs::directory_iterator end_itr;
                for (fs::directory_iterator itr( pdts_folder ); itr != end_itr; ++itr )
                {
                    if(fs::is_directory(itr->status()))
                    {
                        //not recursing for these utility
                    }
                    else
                    {
                        static boost::regex crlFilter;
                        static const char * crlPattern = "^.*\\.(der|crt|cer|pem)$";
                        static bool crlFilterInit = false;
                        if(!crlFilterInit)
                        {
                            try
                            {
                                crlFilter.assign(crlPattern,boost::regex_constants::perl);
                                crlFilterInit = true;
                            }
                            catch(std::exception& se)
                            {
                                std::ostringstream oss;
                                oss << "Failed to initialize regular expression filter";
                                if(se.what())
                                    oss << ": " << se.what();
                                std::cerr << (oss.str().c_str());
                            }
                        }
                        
                        bool processFile = false;
                        if(crlFilterInit)
                        {
                            boost::smatch what;
                            if( boost::regex_search( itr->path().leaf().string(), what, crlFilter ) )
                            {
                                //the filename matches the filter
                                processFile = true;
                            }
                        }
                        else
                        {
                            //the filter could not be prepared
                            processFile = true;
                        }
                        
                        if(processFile && IsPdts(itr->path().leaf().string()))
                        {
                            boost::filesystem::path ta = pdts_folder;
                            ta /= "BasicHTTPURITrustAnchorRootCert.crt";
                            
                            std::ostringstream output;
                            
                            boost::filesystem::path target = itr->path();
                            
                            std::ostringstream testName;
                            testName << itr->path().leaf();
                            
                            output << g_clientName << " ";
                            output << "--scvp_profile long-term-record" << " ";
                            if(!logging_conf.empty())
                                output << "-l " << logging_conf.c_str() << " ";
                            output << "-n " << testName.str().c_str() << " ";
                            output << "-c " << target.string().c_str() << " ";
                            if(IsPdtsFailure(itr->path().leaf().string()))
                            {
                                output << "-x false" << " ";
                            }
                            
                            if(!wantBacks.empty())
                            {
                                output << "--wantBacks ";
                                std::vector<std::string>::iterator pos;
                                std::vector<std::string>::iterator end = wantBacks.end();
                                for(pos = wantBacks.begin(); pos != end; ++pos)
                                {
                                    output << (*pos) << " ";
                                }
                            }
                            
                            if(NON_DEFAULT == zz)
                            {
                                //use appropriate non-default validation policy OID
                                std::string nonDefaultPolicy = "1.3.6.1.4.1.37623.10.1.5.0";
                                output << "-v " << nonDefaultPolicy.c_str() << " ";
                            }
                            else
                            {
                                //pass in the appropriate path settings values and, optionally, TA
                                if(DEFAULT_WITH_TA == zz)
                                {
                                    output << "-t " << ta.string().c_str() << " ";
                                }
                                AppendPathSettings("DefaultPathSettings", output);
                            }
                            
                            std::cout << output.str().c_str() << std::endl;
                            scriptfile << output.str().c_str() << std::endl;
                        }
                    }
                    
                }//end directory iterator
            }// end if path exists
            else
            {
                std::ostringstream oss;
                oss << "Path to PDTS collection does not exist: " << pdts_folder.c_str();
                std::cerr << (oss.str().c_str());
            }
        } catch(fs::filesystem_error & e) {
            std::cerr << e.what();
        }
    }
}
void output_script_batch_pdts(const std::string& logging_conf, const std::string& output_folder, const std::string& pdts_folder, std::vector<std::string>& wantBacks)
{
    //No batch for PDTS
}

void output_script_lightweight_mfpki(const std::string& logging_conf, const std::string& output_folder, const std::string& mfpki_folder, std::vector<std::string>& wantBacks, const std::string& mfpki_ta)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "MFPKI_DEFAULT_WITH_TA";
            }
            else
            {
                filename << "MFPKI_DEFAULT_OMIT_TA";
            }
        }
        else
        {
            filename << "MFPKI_NON_DEFAULT";
        }
        filename << "_lightweight.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        try {
            if(fs::exists( mfpki_folder ) )
            {
                fs::directory_iterator end_itr;
                for (fs::directory_iterator itr( mfpki_folder ); itr != end_itr; ++itr )
                {
                    if(fs::is_directory(itr->status()))
                    {
                        //not recursing for these utility
                    }
                    else
                    {
                        static boost::regex crlFilter;
                        static const char * crlPattern = "^.*\\.(der|crt|cer|pem)$";
                        static bool crlFilterInit = false;
                        if(!crlFilterInit)
                        {
                            try
                            {
                                crlFilter.assign(crlPattern,boost::regex_constants::perl);
                                crlFilterInit = true;
                            }
                            catch(std::exception& se)
                            {
                                std::ostringstream oss;
                                oss << "Failed to initialize regular expression filter";
                                if(se.what())
                                    oss << ": " << se.what();
                                std::cerr << (oss.str().c_str());
                            }
                        }
                        
                        bool processFile = false;
                        if(crlFilterInit)
                        {
                            boost::smatch what;
                            if( boost::regex_search( itr->path().leaf().string(), what, crlFilter ) )
                            {
                                //the filename matches the filter
                                processFile = true;
                            }
                        }
                        else
                        {
                            //the filter could not be prepared
                            processFile = true;
                        }
                        
                        if(processFile)
                        {
                            boost::filesystem::path ta = mfpki_ta;
                            
                            std::ostringstream output;
                            
                            boost::filesystem::path target = itr->path();
                            
                            std::ostringstream testName;
                            testName << itr->path().leaf();
                            
                            output << g_clientName << " ";
                            output << "--scvp_profile lightweight" << " ";
                            if(!logging_conf.empty())
                                output << "-l " << logging_conf.c_str() << " ";
                            output << "-n " << testName.str().c_str() << " ";
                            output << "-c " << target.string().c_str() << " ";
                            //if(0 != (*pos)->errorCode)
                            //{
                            //    output << "-x false" << " ";
                            //}
                            
                            if(!wantBacks.empty())
                            {
                                output << "--wantBacks ";
                                std::vector<std::string>::iterator pos;
                                std::vector<std::string>::iterator end = wantBacks.end();
                                for(pos = wantBacks.begin(); pos != end; ++pos)
                                {
                                    output << (*pos) << " ";
                                }
                            }
                            
                            if(NON_DEFAULT == zz)
                            {
                                //use appropriate non-default validation policy OID
                                std::string nonDefaultPolicy = "1.3.6.1.4.1.37623.10.1.6.0";
                                output << "-v " << nonDefaultPolicy.c_str() << " ";
                            }
                            else
                            {
                                //pass in the appropriate path settings values and, optionally, TA
                                if(DEFAULT_WITH_TA == zz)
                                {
                                    output << "-t " << ta.string().c_str() << " ";
                                }
                                AppendPathSettings("DefaultPathSettings", output);
                            }
                            
                            std::cout << output.str().c_str() << std::endl;
                            scriptfile << output.str().c_str() << std::endl;
                        }
                    }
                    
                }//end directory iterator
            }// end if path exists
            else
            {
                std::ostringstream oss;
                oss << "Path to MFPKI collection does not exist: " << mfpki_folder.c_str();
                std::cerr << (oss.str().c_str());
            }
        } catch(fs::filesystem_error & e) {
            std::cerr << e.what();
        }
    }
}
void output_script_longterm_mfpki(const std::string& logging_conf, const std::string& output_folder, const std::string& mfpki_folder, std::vector<std::string>& wantBacks, const std::string& mfpki_ta)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "MFPKI_DEFAULT_WITH_TA";
            }
            else
            {
                filename << "MFPKI_DEFAULT_OMIT_TA";
            }
        }
        else
        {
            filename << "MFPKI_NON_DEFAULT";
        }
        filename << "_longterm.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        try {
            if(fs::exists( mfpki_folder ) )
            {
                fs::directory_iterator end_itr;
                for (fs::directory_iterator itr( mfpki_folder ); itr != end_itr; ++itr )
                {
                    if(fs::is_directory(itr->status()))
                    {
                        //not recursing for these utility
                    }
                    else
                    {
                        static boost::regex crlFilter;
                        static const char * crlPattern = "^.*\\.(der|crt|cer|pem)$";
                        static bool crlFilterInit = false;
                        if(!crlFilterInit)
                        {
                            try
                            {
                                crlFilter.assign(crlPattern,boost::regex_constants::perl);
                                crlFilterInit = true;
                            }
                            catch(std::exception& se)
                            {
                                std::ostringstream oss;
                                oss << "Failed to initialize regular expression filter";
                                if(se.what())
                                    oss << ": " << se.what();
                                std::cerr << (oss.str().c_str());
                            }
                        }
                        
                        bool processFile = false;
                        if(crlFilterInit)
                        {
                            boost::smatch what;
                            if( boost::regex_search( itr->path().leaf().string(), what, crlFilter ) )
                            {
                                //the filename matches the filter
                                processFile = true;
                            }
                        }
                        else
                        {
                            //the filter could not be prepared
                            processFile = true;
                        }
                        
                        if(processFile)
                        {
                            boost::filesystem::path ta = mfpki_ta;
                            
                            std::ostringstream output;
                            
                            boost::filesystem::path target = itr->path();
                            
                            std::ostringstream testName;
                            testName << itr->path().leaf();
                            
                            output << g_clientName << " ";
                            output << "--scvp_profile long-term-record" << " ";
                            if(!logging_conf.empty())
                                output << "-l " << logging_conf.c_str() << " ";
                            output << "-n " << testName.str().c_str() << " ";
                            output << "-c " << target.string().c_str() << " ";
                            //if(0 != (*pos)->errorCode)
                            //{
                            //    output << "-x false" << " ";
                            //}
                            
                            if(!wantBacks.empty())
                            {
                                output << "--wantBacks ";
                                std::vector<std::string>::iterator pos;
                                std::vector<std::string>::iterator end = wantBacks.end();
                                for(pos = wantBacks.begin(); pos != end; ++pos)
                                {
                                    output << (*pos) << " ";
                                }
                            }
                            
                            if(NON_DEFAULT == zz)
                            {
                                //use appropriate non-default validation policy OID
                                std::string nonDefaultPolicy = "1.3.6.1.4.1.37623.10.1.6.0";
                                output << "-v " << nonDefaultPolicy.c_str() << " ";
                            }
                            else
                            {
                                //pass in the appropriate path settings values and, optionally, TA
                                if(DEFAULT_WITH_TA == zz)
                                {
                                    output << "-t " << ta.string().c_str() << " ";
                                }
                                AppendPathSettings("DefaultPathSettings", output);
                            }
                            
                            std::cout << output.str().c_str() << std::endl;
                            scriptfile << output.str().c_str() << std::endl;
                        }
                    }
                    
                }//end directory iterator
            }// end if path exists
            else
            {
                std::ostringstream oss;
                oss << "Path to MFPKI collection does not exist: " << mfpki_folder.c_str();
                std::cerr << (oss.str().c_str());
            }
        } catch(fs::filesystem_error & e) {
            std::cerr << e.what();
        }
    }
}
void output_script_batch_mfpki(const std::string& logging_conf, const std::string& output_folder, const std::string& mfpki_folder, std::vector<std::string>& wantBacks, const std::string& mfpki_ta)
{
    //for each profile, three editions of scripts are generated: default policy w/TA inclusion, default policy w/TA omission, non-default policy
    for(int zz = 0; zz < 3; ++zz)
    {
        std::ofstream scriptfile;
        boost::filesystem::path path = output_folder;
        std::ostringstream filename;
        
        std::string testName;
        bool defaultPolicy = false;
        bool includeTa = false;
        if(NON_DEFAULT != zz)
        {
            defaultPolicy = true;
            if(DEFAULT_WITH_TA == zz)
            {
                includeTa = true;
                filename << "MFPKI_DEFAULT_WITH_TA";
                testName = "\"MFPKI batch default validation policy with TA specified\"";
            }
            else
            {
                filename << "MFPKI_DEFAULT_OMIT_TA";
                testName = "\"MFPKI batch default validation policy without TA specified\"";
            }
        }
        else
        {
            filename << "MFPKI_NON_DEFAULT";
            testName = "\"MFPKI batch non-default validation policy\"";
        }
        filename << "_batch.sh";
        path /= filename.str().c_str();
        scriptfile.open(path.string().c_str());
        
        boost::filesystem::path ta = mfpki_ta;
        
        std::ostringstream output;
        
        boost::filesystem::path target = mfpki_folder;
        
        output << g_clientName << " ";
        output << "--scvp_profile batch" << " ";
        if(!logging_conf.empty())
            output << "-l " << logging_conf.c_str() << " ";
        output << "-n " << testName.c_str() << " ";
        output << "--batch_folder_success " << target.string().c_str() << " ";
        //if(0 != (*pos)->errorCode)
        //{
        //    output << "-x false" << " ";
        //}
        
        if(NON_DEFAULT == zz)
        {
            //use appropriate non-default validation policy OID
            std::string nonDefaultPolicy = "1.3.6.1.4.1.37623.10.1.6.0";
            output << "-v " << nonDefaultPolicy.c_str() << " ";
        }
        else
        {
            //pass in the appropriate path settings values and, optionally, TA
            if(DEFAULT_WITH_TA == zz)
            {
                output << "-t " << ta.string().c_str() << " ";
            }
            AppendPathSettings("DefaultPathSettings", output);
        }
        
        std::cout << output.str().c_str() << std::endl;
        scriptfile << output.str().c_str() << std::endl;
    }
}


