package gov.treas.pki.vss.scvp;

//--------------------------------------------------------------------------------------------------------------
//region Imports
//--------------------------------------------------------------------------------------------------------------
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import gov.treas.pki.vss.rest.json.ResultByCertificate;
import gov.treas.pki.vss.rest.json.VSSResponse;
import gov.treas.pki.vss.rest.json.WantBackTypeToken;
import gov.treas.pki.vss.scvp.asn1.*;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.message.ObjectArrayMessage;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import gov.treas.pki.httpclient.HttpClient;
import gov.treas.pki.httpclient.HttpClientException;
import gov.treas.pki.vss.crypto.DigestEngine;
import gov.treas.pki.vss.properties.VSSGlobalProperties;

import net.sourceforge.argparse4j.ArgumentParsers;
import org.bouncycastle.util.Store;

//--------------------------------------------------------------------------------------------------------------
// endregion
//--------------------------------------------------------------------------------------------------------------

public class TestProgramSCVPClient
{

	//private static final Logger LOG = LogManager.getLogger(TestProgramSCVPClient.class);
	private static final Logger LOG_ARTIFACTS = LogManager.getLogger("gov.gsa.scvp_test.artifacts");
	private static final Logger LOG_RESULTS = LogManager.getLogger("gov.gsa.scvp_test.results");
	private static final Logger LOG_CLIENT = LogManager.getLogger("gov.gsa.scvp_test.client");
	private static final Logger LOG_VALIDATION_FAILURES = LogManager.getLogger("gov.gsa.scvp_test.validation-failures");
	private static final Logger LOG_PROFILE_FAILURES = LogManager.getLogger("gov.gsa.scvp_test.profile-failures");

	private Provider jceProvider = null;
	private byte[] fullRequest = null;
	private byte[] fullResponse = null;

	String target_cert = null;
	String val_policy = null;
	List<String> policies = null;
	List<ASN1ObjectIdentifier> wantBacks = null;
	List<WantBackTypeToken> wantBackTypeTokens = null;
	Boolean iapSet = false, iap = false;
	Boolean ipmSet = false, ipm = false;
	Boolean repSet = false, rep = false;
	List<String> tas = null;
	String batch_folder = null;
	String batch_folder_success = null;
	String batch_folder_failure = null;
	String scvp_profile = null;
	Boolean expectSuccess = true;
	String logging_conf = null;
	String test_case_name = "";
	String timestamp = null;

	public TestProgramSCVPClient(Provider jceProvider)
	{
		this.jceProvider = jceProvider;
	}

	/**
	 * @return the fullRequest
	 */
	public byte[] getFullRequest() {
		return fullRequest;
	}

	/**
	 * @return the fullResponse
	 */
	public byte[] getFullResponse() {
		return fullResponse;
	}

	public static String GetReplyStatusAsString(ReplyStatus rs)
	{
		int stat = rs.getValue().intValue();
		if(ReplyStatus.SUCCESS == stat)
		{
			return "success";
		}
		else if(ReplyStatus.CERTPATHCONSTRUCTFAIL == stat)
		{
			return "certification path construction failed";
		}
		else if(ReplyStatus.CERTPATHNOTVALID == stat)
		{
			return "certification path not valid";
		}
		else if(ReplyStatus.CERTPATHNOTVALIDNOW == stat)
		{
			return "certification path not valid now";
		}
		else if(ReplyStatus.MALFORMEDAC == stat)
		{
			return "malformed attribute certificate";
		}
		else if(ReplyStatus.MALFORMEDPKC == stat)
		{
			return "malformed public key certificate";
		}
		else if(ReplyStatus.REFERENCECERTHASHFAIL == stat)
		{
			return "reference certificate hash failure";
		}
		else if(ReplyStatus.UNAVAILABLEVALIDATIONTIME == stat)
		{
			return "unavailable validation time";
		}
		else if(ReplyStatus.WANTBACKUNSATISFIED == stat)
		{
			return "want back unsatisfied";
		}
		return "unrecognized ReplyStatus";
	}

	public static String GetReplyCheckAsString(ReplyCheck rc)
	{
		//Note, the values returned here are not correct for DPD

		ASN1Integer stat = rc.getStatus();
		if(new ASN1Integer(0).equals(stat))
		{
			return "valid";
		}
		else if(new ASN1Integer(1).equals(stat))
		{
			return "not valid";
		}
		else if(new ASN1Integer(2).equals(stat))
		{
			return "revocation off-line";
		}
		else if(new ASN1Integer(3).equals(stat))
		{
			return "revocation unavailable";
		}
		else if(new ASN1Integer(4).equals(stat))
		{
			return "no known source for revocation information";
		}
		return "unrecognized ReplyCheck status";
	}

	//--------------------------------------------------------------------------------------------------------------
	//region get_signers_cert
	//--------------------------------------------------------------------------------------------------------------
	public static void get_signers_cert(byte[] resBytes)
	{
		CMSSignedData s = null;
		ValPolResponse vpResponse = null;
		ContentInfoParser contentInfoParser = null;
		if (null != resBytes) {
			ASN1SequenceParser seqPar = null;
			ASN1ObjectIdentifier contentType = null;
			ASN1StreamParser streamParser = new ASN1StreamParser(resBytes);
			Object object = null;
			try {
				object = streamParser.readObject();
			} catch (IOException e) {
				LOG_CLIENT.error("Error parsing the SCVP Response bytes", e);
			}
			if (object instanceof ASN1SequenceParser) {
				seqPar = (ASN1SequenceParser) object;
				try {
					contentInfoParser = new ContentInfoParser(seqPar);
				} catch (IOException e) {
					LOG_CLIENT.error("Error parsing the SCVP Response ContentInfo", e);
				}
				if (null != contentInfoParser) {
					contentType = contentInfoParser.getContentType();
					if (CMSObjectIdentifiers.signedData.equals(contentType)) {
						try {
							s = new CMSSignedData(resBytes);

							Store certStore = s.getCertificates();
							Collection c = certStore.getMatches(null);
							Iterator cit = c.iterator();
							int counter = 0;
							while(cit.hasNext())
							{
								X509CertificateHolder cert = (X509CertificateHolder)cit.next();
								counter++;
								try {
									String filename = "certificate_" + Integer.toString(counter) + ".der";
									FileOutputStream fos = new FileOutputStream(filename);
									fos.write(cert.getEncoded());
									fos.close();
									LOG_CLIENT.info("Wrote certificate to " + filename);
								}
								catch(Exception e)
								{
									LOG_CLIENT.error("Failed to write certificate read from validation policy response: ", e);
								}
							}
							return;
						} catch (CMSException e) {
							LOG_CLIENT.error("Error parsing CMS Signed Data: ", e);
						}
					} else {
						LOG_CLIENT.error("Response was not CMS Signed Data");
					}
				}
			} else {
				LOG_CLIENT.error("Error parsing the SCVP Response as a SEQUENCE");
			}
		} else {
			LOG_CLIENT.error("SCVP Response was NULL");
		}
	}
	//--------------------------------------------------------------------------------------------------------------
	// endregion
	//--------------------------------------------------------------------------------------------------------------

	public static void LogFailureForPrematureExit(TestProgramSCVPClient client, String target, String jarName, String params, long start)
	{
		LOG_RESULTS.info(new ObjectArrayMessage(client.timestamp, client.test_case_name, target, client.expectSuccess, "unknown", "unknown"));
		LOG_CLIENT.info("Finished test case " + client.test_case_name + " in " + (System.currentTimeMillis() - start) + " milliseconds: " + "unknown" + "/" + "unknown");
	}

	public static void main(String args[]) {

		long start = System.currentTimeMillis();
		String jarName = new java.io.File(TestProgramSCVPClient.class.getProtectionDomain()
				.getCodeSource()
				.getLocation()
				.getPath())
				.getName();

		/*
		 * The intent is to change the provider for the cryptographic
		 * operations. I.e., a FIPS provider if needed. For now, we will use the
		 * BouncyCastle API since that is what we use for the ASN.1
		 */
		Provider jceProvider = new BouncyCastleProvider();
		Security.addProvider(jceProvider);

		TestProgramSCVPClient client = new TestProgramSCVPClient(jceProvider);
		SCVPClient scvp = new SCVPClient();
		SCVPClient.CustomParametersAndResults cp = new SCVPClient.CustomParametersAndResults();
		VSSGlobalProperties vgp = VSSGlobalProperties.getInstance();
		Boolean log_all = false;

		StringBuilder builder = new StringBuilder();
		for(String s : args) {
			builder.append(s + " ");
		}
		String params = builder.toString();

		//--------------------------------------------------------------------------------------------------------------
		//region Parameter parsing
		//--------------------------------------------------------------------------------------------------------------
		ArgumentParser parser = ArgumentParsers.newArgumentParser("TestProgramSCVPClient")
				.defaultHelp(true)
				.description("Validates a target certificate using a given SCVP server and set of criteria.");

		ArgumentGroup logistics = parser.addArgumentGroup("Basic Logistics");
		logistics.addArgument( "--scvp_profile").choices("lightweight", "long-term-record", "batch").setDefault("lightweight")
				.help("Name of SCVP profile.");
		logistics.addArgument("-x", "--expectSuccess").setDefault(true).type(Boolean.class)
				.help("Boolean value indicating whether success is expected. Applies to either --target_cert or all certs in --batch_folder_success");
		logistics.addArgument("-l", "--logging_conf")
				.help("Full path and filename of log4j configuration file (to customize default logging behavior).");
		logistics.addArgument("-n", "--test_case_name")
				.help("Friendly name of test case (mostly for logging purposes).");
		logistics.addArgument("-z", "--signer_certs")
				.help("Save signer certs to specified directory as read from a validation policy response then exit.");
		logistics.addArgument("--log_all_messages").action(Arguments.storeTrue())
				.help("Log all request and response messages. Off by default.");

		ArgumentGroup targetDetails = parser.addArgumentGroup("Target Certificate Details");
		targetDetails.addArgument("-c", "--target_cert")
				.help("Full path and filename of certificate to validate. Not used when --scvp_profile is set to batch, required otherwise.");
		targetDetails.addArgument("-b", "--batch_folder")
				.help("Full path of folder containing binary DER encoded certificates to specify as targets in a single CVRequest. Required when --scvp_profile is set to batch and omitted otherwise.");
		targetDetails.addArgument("-t", "--trust_anchor").nargs("*")
				.help("Full path and filename to file containing binary DER encoded certificate to use as a trust anchor. Omitted from request by default.");
		targetDetails.addArgument("--batch_folder_success")
				.help("Full path of folder containing binary DER encoded certificates to specify as targets in a single CVRequest where all certs should validate successfully. Used when --scvp_profile is set to batch and ignored otherwise.");
		targetDetails.addArgument("--batch_folder_failure")
				.help("Full path of folder containing binary DER encoded certificates to specify as targets in a single CVRequest where all certs should fail to validate successfully. Used when --scvp_profile is set to batch and ignored otherwise.");

		ArrayList<String> defWantBacks = new ArrayList<String>();
		defWantBacks.add("BestCertPath");

		ArgumentGroup requestDetails = parser.addArgumentGroup("SCVP Request Details");
		requestDetails.addArgument("-v", "--validation_policy").setDefault("1.3.6.1.5.5.7.19.1")
				.help("Validation policy to include in the SCVP request. Object identifiers are expressed in dot notation form: 1.2.3.4.5.");
		requestDetails.addArgument("--wantBacks").nargs("*").choices("Cert", "BestCertPath","RevocationInfo","PublicKeyInfo","AllCertPaths","EeRevocationInfo","CAsRevocationInfo")
				.help("Want back values to include in as CVRequest.query.wantBack.");
		ArgumentGroup valInputs = parser.addArgumentGroup("Certification Path Validation Algorithm Inputs");
		valInputs.addArgument("-p", "--certificate_policy").nargs("*")
				.help("Certificate policy or policies to use as CVRequest.query.validationPolicy.userPolicySet. Object identifiers are expressed in dot notation form: 1.2.3.4.5 2.3.4.5.6 etc. Omitted from request by default.");
		valInputs.addArgument("--inhibitAnyPolicy").type(Boolean.class)
				.help("Boolean value to use as CVRequest.query.validationPolicy.inhibitAnyPolicy. Omitted from request by default.");
		valInputs.addArgument("--inhibitPolicyMapping").type(Boolean.class)
				.help("Boolean value to use as CVRequest.query.validationPolicy.inhibitPolicyMapping. Omitted from request by default.");
		valInputs.addArgument("--requireExplicitPolicy").type(Boolean.class)
				.help("Boolean value to use as CVRequest.query.validationPolicy.requireExplicitPolicy. Omitted from request by default.");

		Namespace ns = null;
		try {
			ns = parser.parseArgs(args);
		} catch (ArgumentParserException e) {
			parser.handleError(e);
			System.exit(1);
		}
		//--------------------------------------------------------------------------------------------------------------
		//endregion
		//--------------------------------------------------------------------------------------------------------------

		//--------------------------------------------------------------------------------------------------------------
		//region Harvest values from parameters
		//--------------------------------------------------------------------------------------------------------------
		Map<String,Object> m = ns.getAttrs();
		if(null != m.get("target_cert")) {
			client.target_cert = ns.getString("target_cert");
		}
		if(null != m.get("validation_policy")) {
			client.val_policy = ns.getString("validation_policy");
		}

		//make sure scvp_profile is read before wantBacks so we admonish the user to refrain from passing wantBacks
		//when executing batch tests.
		if(null != m.get("scvp_profile")) {
			client.scvp_profile = ns.getString("scvp_profile");
		}
		if(null != m.get("wantBacks")) {

			if("batch".equals(client.scvp_profile))
			{
				LOG_CLIENT.info("INFO: batch requests MUST NOT include wantBacks. ignoring wantBacks and continuing.");
			}
			else {
				client.wantBacks = new ArrayList<ASN1ObjectIdentifier>();
				client.wantBackTypeTokens = new ArrayList<WantBackTypeToken>();
				List<String> wantBacks = ns.<String>getList("wantBacks");
				for (String wb : wantBacks) {
					if (wb.equals("PkcCert")) {
						client.wantBacks.add(WantBack.idSwbPkcCert);
					} else if (wb.equals("BestCertPath")) {
						client.wantBacks.add(WantBack.idSwbPkcBestCertPath);
						WantBackTypeToken wbtt = new WantBackTypeToken();
						wbtt.wantBackTypeToken = "certPath";
						client.wantBackTypeTokens.add(wbtt);
					} else if (wb.equals("RevocationInfo")) {
						client.wantBacks.add(WantBack.idSwbPkcRevocationInfo);
						WantBackTypeToken wbtt = new WantBackTypeToken();
						wbtt.wantBackTypeToken = "revocationInfo";
						client.wantBackTypeTokens.add(wbtt);
					} else if (wb.equals("PublicKeyInfo")) {
						client.wantBacks.add(WantBack.idSwbPkcPublicKeyInfo);
					} else if (wb.equals("AllCertPaths")) {
						client.wantBacks.add(WantBack.idSwbPkcAllCertPaths);
					} else if (wb.equals("EeRevocationInfo")) {
						client.wantBacks.add(WantBack.idSwbPkcEeRevocationInfo);
					} else if (wb.equals("CAsRevocationInfo")) {
						client.wantBacks.add(WantBack.idSwbPkcCAsRevocationInfo);
					}
				}
			}
		}
		if(null != m.get("trust_anchor")) {
			client.tas = ns.<String>getList("trust_anchor");
		}
		if(null != m.get("batch_folder")) {
			client.batch_folder = ns.getString("batch_folder");
		}
		if(null != m.get("batch_folder_success")) {
			client.batch_folder_success = ns.getString("batch_folder_success");
		}
		if(null != m.get("batch_folder_failure")) {
			client.batch_folder_failure = ns.getString("batch_folder_failure");
		}
		if(null != m.get("expectSuccess")) {
			client.expectSuccess = ns.getBoolean("expectSuccess");
		}
		if(null != m.get("logging_conf")) {
			client.logging_conf = ns.getString("logging_conf");
		}
		if(null != m.get("test_case_name")) {
			client.test_case_name = ns.getString("test_case_name");
		}
		client.timestamp = new java.text.SimpleDateFormat("MM/dd/yyyy HH:mm:ss").format(new java.util.Date());

		if(null != m.get("certificate_policy")) {
			client.policies = ns.<String>getList("certificate_policy");

			//sanity check the OID values
			try {
				if(null != client.policies) {
					for (String policy : client.policies) {
						ASN1ObjectIdentifier id = new ASN1ObjectIdentifier(policy);
					}
				}
			} catch(IllegalArgumentException e) {
				LOG_CLIENT.error("ERROR: Invalid Policy OID: " + e.getLocalizedMessage());

				LogFailureForPrematureExit(client, "", jarName, params, start);
				return;
			}

			cp.setUserPolicySet(client.policies);
		}
		if(null != m.get("log_all_messages")) {
			log_all = true;
		}

		if(null != m.get("inhibitAnyPolicy")) {
			client.iap = ns.getBoolean("inhibitAnyPolicy");
			client.iapSet = true;
			cp.setInhibitAnyPolicy(client.iap);
		}
		if(null != m.get("inhibitPolicyMapping")) {
			client.ipm = ns.getBoolean("inhibitPolicyMapping");
			client.ipmSet = true;
			cp.setInhibitPolicyMapping(client.ipm);
		}
		if(null != m.get("requireExplicitPolicy")) {
			client.rep = ns.getBoolean("requireExplicitPolicy");
			client.repSet = true;
			cp.setRequireExplicitPolicy(client.rep);
		}

		if(client.scvp_profile.equals("lightweight")){
			ResponseFlags rf = new ResponseFlags(false, true, true, true);
			cp.setResponseFlags(rf);
		}
		else if(client.scvp_profile.equals("long-term-record")){
			ResponseFlags rf = new ResponseFlags(true, false, true, false);
			cp.setResponseFlags(rf);

			//Long-term requests are required to contain requestorText that conforms to a very specific structure
			String location = "PHY"; //physical resource
			String fieldSeparator = ";";
			String lo = "LO";
			//String fieldSeparator = ";";
			String agency = "4700"; //General Services Administration
			String street = "     4701A";
			String streetName = "                                        Elm Street";
			String city = "            New York";
			String state = "NY";
			String zip = "     12345";
			String country = " United States of America";
			String accessPoint = "            AP 12345";
			String futureUse = "                                                                                                     ";
			String phyRequestorText = location + fieldSeparator + lo + fieldSeparator + agency + street + streetName + city + state + zip + country + accessPoint + futureUse;
			cp.setRequestorText(phyRequestorText);
			cp.setNonceSize(20);
		}
		else if(client.scvp_profile.equals("batch"))
		{
			ResponseFlags rf = new ResponseFlags(false, true, true, true);
			cp.setResponseFlags(rf);
		}
		else {
			LOG_CLIENT.error("ERROR: unrecognized SCVP profile value specified");
		}

		//--------------------------------------------------------------------------------------------------------------
		//endregion
		//--------------------------------------------------------------------------------------------------------------

		//--------------------------------------------------------------------------------------------------------------
		//region Execute signer_certs command and exit
		//--------------------------------------------------------------------------------------------------------------
		if(null != m.get("signer_certs")) {
			try {
				byte[] resBytes = null;
				try {
					ValPolRequest policyRequest = new ValPolRequest(null);
					ServerPolicyRequest encapReq = new ServerPolicyRequest(policyRequest);
					byte[] rawReq = null;
					try {
						rawReq = encapReq.toASN1Primitive().getEncoded();
					} catch (IOException e) {
						LOG_CLIENT.error("Failed to encode Server Policy Request");
					}
					HttpClient httpclient = HttpClient.getInstance();
					resBytes = httpclient.postRequest(vgp.getScvpServerURI(), rawReq, HttpClient.MIME_VP_REQUEST,
							HttpClient.MIME_VP_RESPONSE);
				} catch (HttpClientException e) {
					LOG_CLIENT.error("Error communicating with SCVP Service for a Policy Request", e);
				}
				if(null != resBytes) {
					String filename = "vp.der";
					FileOutputStream fos = new FileOutputStream(filename);
					fos.write(resBytes);
					fos.close();
					get_signers_cert(resBytes);
				}
				else {
					LOG_CLIENT.error("Failed to obtain validation policy response while trying to get SCVP responder certificate");
				}
				return;
			}
			catch(Exception e)
			{
				LOG_CLIENT.error("Failed to retrieve SCVP server certificate");
				LogFailureForPrematureExit(client, "", jarName, params, start);
				return;
			}
		}
		//--------------------------------------------------------------------------------------------------------------
		//endregion
		//--------------------------------------------------------------------------------------------------------------

		if(null != client.logging_conf) {
			try {
				Configurator.initialize(null, client.logging_conf);
			} catch (Exception e) {
				System.out.print(e.toString());
			}
		}

		if(null == client.target_cert && null == client.batch_folder && null == client.batch_folder_success && null == client.batch_folder_failure)
		{
			parser.printHelp();
			return;
		}

		String target = client.target_cert;
		if(null == target)
		{
			target = client.batch_folder;
		}
		if(null == target)
		{
			target = client.batch_folder_success;
		}
		if(null == target)
		{
			target = client.batch_folder_failure;
		}

		VSSResponse vr = new VSSResponse();

		LOG_CLIENT.info("");
		LOG_CLIENT.info("Executing test case " + client.test_case_name);
		LOG_CLIENT.info("SCVP server: " + vgp.getScvpServerURI());
		LOG_CLIENT.info("Parameters: " + params);

		//ArrayList<X509Certificate> endEntityCertsForReq = new ArrayList<X509Certificate>();
		ArrayList<X509Certificate> endEntityCerts = new ArrayList<X509Certificate>();
		ArrayList<X509Certificate> endEntityCertsSuccess = new ArrayList<X509Certificate>();
		ArrayList<X509Certificate> endEntityCertsFailure = new ArrayList<X509Certificate>();
		ArrayList<String> expectSuccess = new ArrayList<String>();
		Map<String, String> succMap = new HashMap<String, String>();
		ArrayList<String> expectFailure = new ArrayList<String>();
		Map<String, String> failMap = new HashMap<String, String>();
		if(null != client.target_cert) {
			try {
				CertificateFactory cf = CertificateFactory.getInstance("X.509", jceProvider.getName());
				X509Certificate endEntityCert = (X509Certificate) cf.generateCertificate(new FileInputStream(client.target_cert));
				endEntityCerts.add(endEntityCert);
			} catch (NoSuchProviderException e) {
				LOG_CLIENT.error("There was a problem with the JCE provider: " + e.getMessage());
			} catch (CertificateException e) {
				LOG_CLIENT.error("There was a problem with the certificate: " + e.getMessage());
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				LOG_CLIENT.error("No such file: " + client.target_cert);
			}
		}
		else {
			if (null != client.batch_folder) {
				File batch_folder = new File(client.batch_folder);
				File[] files = batch_folder.listFiles();
				if (null != files) {
					for (File certFile : files) {
						try {
							CertificateFactory cf = CertificateFactory.getInstance("X.509", jceProvider.getName());
							X509Certificate endEntityCert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
							if (null != endEntityCert) {
								endEntityCerts.add(endEntityCert);
								endEntityCerts.add(endEntityCert);
							}
						} catch (NoSuchProviderException e) {
							LOG_CLIENT.error("There was a problem with the JCE provider: " + e.getMessage());
						} catch (CertificateException e) {
							LOG_CLIENT.error("There was a problem with the certificate: " + e.getMessage());
							e.printStackTrace();
						} catch (FileNotFoundException e) {
							LOG_CLIENT.error("No such file: " + certFile);
						}
					}
				}
			}
			else
			{
				if (null != client.batch_folder_success) {
					File batch_folder = new File(client.batch_folder_success);
					File[] files = batch_folder.listFiles();
					if (null != files) {
						for (File certFile : files) {
							try {
								CertificateFactory cf = CertificateFactory.getInstance("X.509", jceProvider.getName());
								X509Certificate endEntityCert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
								if (null != endEntityCert) {
									endEntityCertsSuccess.add(endEntityCert);
									endEntityCerts.add(endEntityCert);

									byte[] encCert = endEntityCert.getEncoded();
									byte[] sha1 = DigestEngine.sHA1Sum(encCert);
									String sha1Hex = Hex.encodeHexString(sha1);
									expectSuccess.add(sha1Hex);
									succMap.put(sha1Hex, certFile.getName());
								}
							} catch (NoSuchProviderException e) {
								LOG_CLIENT.error("There was a problem with the JCE provider: " + e.getMessage());
							} catch (CertificateException e) {
								LOG_CLIENT.error("There was a problem with the certificate: " + e.getMessage());
								e.printStackTrace();
							} catch (FileNotFoundException e) {
								LOG_CLIENT.error("No such file: " + certFile);
							}
						}
					}
				}
				if (null != client.batch_folder_failure) {
					File batch_folder = new File(client.batch_folder_failure);
					File[] files = batch_folder.listFiles();
					if (null != files) {
						for (File certFile : files) {
							try {
								CertificateFactory cf = CertificateFactory.getInstance("X.509", jceProvider.getName());
								X509Certificate endEntityCert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
								if (null != endEntityCert) {
									endEntityCertsFailure.add(endEntityCert);
									endEntityCerts.add(endEntityCert);

									byte[] encCert = endEntityCert.getEncoded();
									byte[] sha1 = DigestEngine.sHA1Sum(encCert);
									String sha1Hex = Hex.encodeHexString(sha1);
									expectFailure.add(sha1Hex);
									failMap.put(sha1Hex, certFile.getName());
								}
							} catch (NoSuchProviderException e) {
								LOG_CLIENT.error("There was a problem with the JCE provider: " + e.getMessage());
							} catch (CertificateException e) {
								LOG_CLIENT.error("There was a problem with the certificate: " + e.getMessage());
								e.printStackTrace();
							} catch (FileNotFoundException e) {
								LOG_CLIENT.error("No such file: " + certFile);
							}
						}
					}
				}
			}
		}

		if(null == endEntityCerts || 0 == endEntityCerts.size())
		{
			LOG_CLIENT.error("ERROR: Neither target_cert nor a batch_folder parameter yielded any certificates to validate.");
			LogFailureForPrematureExit(client, target, jarName, params, start);
			return;
		}

		boolean passed_profile_checks = true;
		String valCheck = "unknown";

		try {
			vr = scvp.validate(endEntityCerts, new ASN1ObjectIdentifier(client.val_policy), client.wantBackTypeTokens, cp, vr);
		}
		catch(Exception e) {
			LOG_CLIENT.error("Unexpected exception during " + client.test_case_name + ": " + e.toString());
			LogFailureForPrematureExit(client, target, jarName, params, start);
			return;
		}
		if (null == vr) {
			LOG_CLIENT.error("Failed to get response");
			LogFailureForPrematureExit(client, target, jarName, params, start);
			return;
		}

		if (client.scvp_profile.equals("lightweight") || client.scvp_profile.equals("long-term-record")) {
			if (!"SUCCESS".equals(vr.transactionResult.transactionResultToken)) {
				passed_profile_checks = false;
			}
		} else {
			if ("SUCCESS".equals(vr.transactionResult.transactionResultToken)) {
				for (ResultByCertificate rbc : vr.validationResult.resultsByCertificateList) {
					if (!"SUCCESS".equals(rbc.resultByCertificate.validationResultToken)) {
						passed_profile_checks = false;
					}
				}
			} else {
				passed_profile_checks = false;
			}
		}

		byte[] rawReq = cp.getFullRequest();
		byte[] resp = cp.getFullResponse();
		if (!passed_profile_checks || log_all) {
			//Base64 b = new Base64(76, "\n".getBytes());
			String encodedRequest = "";
			if(null != rawReq) {
				encodedRequest = new String(Base64.encodeBase64(rawReq, true));
			}
			String encodedResponse = "";
			if(null != resp) {
				encodedResponse = new String(Base64.encodeBase64(resp, true));
			}
			LOG_ARTIFACTS.info(new ObjectArrayMessage(client.timestamp, client.test_case_name, encodedRequest, encodedResponse));
		}

		CVResponse cvResponse = cp.getCvResponse();
		if(cvResponse == null)
		{
			LOG_CLIENT.error("Expected to find CVResponse but did not");
			valCheck = "unknown";
			passed_profile_checks = false;
		}
		else //profile checks
		{
			try {
				if (client.scvp_profile.equals("lightweight") || client.scvp_profile.equals("long-term-record") ||
						client.scvp_profile.equals("batch")) {
					//---------------------------------------------------------------------------------------------------------
					// Several elements of the SCVP requests apply to all three profiles
					//---------------------------------------------------------------------------------------------------------

					// The request will have requested id-stc-build-status-checked-pkc-path so the response should have a
					// ReplyCheck with the same.

					ASN1Integer success = new ASN1Integer(0);
					List<CertReply> replyObjects = cvResponse.getReplyObjects();
					for (CertReply certReply : replyObjects) {

						ReplyStatus rs = certReply.getReplyStatus();
						Certificate cert = certReply.getCertReference().getPkc().getCert();

						String replyStatusString = GetReplyStatusAsString(rs);

						ReplyChecks replyChecks = certReply.getReplyChecks();
						ReplyCheck[] replyChecksValues = replyChecks.getReplyChecks();

						if (1 != replyChecksValues.length) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected 1 ReplyCheck but found " + Integer.toString(replyChecksValues.length));
						}

						for (int ii = 0; ii < replyChecksValues.length; ++ii) {
							ReplyCheck rc = replyChecksValues[ii];
							if (!rc.getCheck().equals(CertChecks.idStcBuildStatusCheckedPkcPath)) {
								passed_profile_checks = false;
								LOG_CLIENT.error("Expected 1 ReplyCheck set to " + CertChecks.idStcBuildStatusCheckedPkcPath + "  but found " + rc.getCheck());
							}

							String replyCheckString = GetReplyCheckAsString(rc);

							if (client.scvp_profile.equals("lightweight") || client.scvp_profile.equals("long-term-record")) {

								if ("unknown".equals(valCheck)) {
									valCheck = "passed";
								}

								if (rc.getStatus().equals(success) && client.expectSuccess) {
									LOG_CLIENT.info("Path validation succeeded as expected");
								} else if (!rc.getStatus().equals(success) && !client.expectSuccess) {
									LOG_CLIENT.info("Path validation failed as expected");
								} else if (!rc.getStatus().equals(success) && client.expectSuccess) {
									LOG_CLIENT.error("Expected path validation to succeed but ReplyCheck indicates " + rc.getStatus().toString() + " (" + replyCheckString + ")" + " and ReplyStatus indicates " + rs.getValue().toString() + " (" + replyStatusString + ")");
									valCheck = "failed";
								} else if (rc.getStatus().equals(success) && !client.expectSuccess) {
									LOG_CLIENT.error("Expected path validation to fail but ReplyCheck indicates " + rc.getStatus().toString() + " (" + replyCheckString + ")" + " and ReplyStatus indicates " + rs.getValue().toString() + " (" + replyStatusString + ")");
									valCheck = "failed";
								}
							} else if (null != client.batch_folder_failure || null != client.batch_folder_success) {
								boolean expectSuccessBatch = false;
								String sha1Hex = null;
								try {
									byte[] encCert = cert.getEncoded();
									byte[] sha1 = DigestEngine.sHA1Sum(encCert);
									sha1Hex = Hex.encodeHexString(sha1);
									expectSuccessBatch = expectSuccess.contains(sha1Hex);
								} catch (Exception e) {
									LOG_CLIENT.error("Failed to has certificate from file " + succMap.get(sha1Hex) + " to determine if success was expected: " + e.getLocalizedMessage());
								}
								if ("unknown".equals(valCheck)) {
									valCheck = "passed";
								}
								if (rc.getStatus().equals(success) && expectSuccessBatch) {
									LOG_CLIENT.info("Path validation succeeded as expected" + " for certificate from file " + succMap.get(sha1Hex));
								} else if (!rc.getStatus().equals(success) && !expectSuccessBatch) {
									LOG_CLIENT.info("Path validation failed as expected" + " for certificate from file " + failMap.get(sha1Hex));
								} else if (!rc.getStatus().equals(success) && expectSuccessBatch) {
									LOG_CLIENT.error("Expected path validation to succeed but ReplyCheck indicates " + rc.getStatus().toString() + " (" + replyCheckString + ")" + " and ReplyStatus indicates " + rs.getValue().toString() + " (" + replyStatusString + ")" + " for certificate from file " + succMap.get(sha1Hex));
									valCheck = "failed";
								} else if (rc.getStatus().equals(success) && !expectSuccessBatch) {
									LOG_CLIENT.error("Expected path validation to fail but ReplyCheck indicates " + rc.getStatus().toString() + " (" + replyCheckString + ")" + " and ReplyStatus indicates " + rs.getValue().toString() + " (" + replyStatusString + ")" + " for certificate from file " + failMap.get(sha1Hex));
									valCheck = "failed";
								}

							}
						}
					}

					// Confirm the request is a SignedData
					if (null == cp.getCms()) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected to find a CMS SignedData layer but did not");
					}
				}
				if (client.scvp_profile.equals("lightweight") || client.scvp_profile.equals("long-term-record")) {
					//---------------------------------------------------------------------------------------------------------
					// Some elements of the SCVP requests apply to lightweight and long-term-record only
					//---------------------------------------------------------------------------------------------------------
					// The request will have had exactly one certificate reference, so the response should have exactly one
					// certificate reply. The spec is somewhat vague but section 4 states the following:
					//		"The replyObjects item MUST contain exactly one CertReply item for each certificate requested."
					List<CertReply> replyObjects = cvResponse.getReplyObjects();

					if (1 != replyObjects.size()) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected 1 ReplyObject but found " + Integer.toString(replyObjects.size()));
					}

					// The wantBacks field should contain the same list as was passed into validate.
					for (CertReply certReply : replyObjects) {
						ReplyChecks replyChecks = certReply.getReplyChecks();
						ReplyCheck[] replyChecksValues = replyChecks.getReplyChecks();

						ReplyWantBacks rwb = certReply.getReplyWantBacks();
						ASN1ObjectIdentifier[] oids = rwb.getReplyWantBackOIDs();

						if (oids.length != client.wantBacks.size() && client.expectSuccess) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected " + Integer.toString(client.wantBacks.size()) + " WantBack(s) but found " + Integer.toString(oids.length));
						}

						for (int ii = 0; ii < oids.length; ++ii) {
							if (!client.wantBacks.contains(oids[ii])) {
								passed_profile_checks = false;
								LOG_CLIENT.error("Found unexpected WantBack: " + oids[ii]);
							}
						}
					}
				}

				if (client.scvp_profile.equals("lightweight") || client.scvp_profile.equals("batch")) {
					//---------------------------------------------------------------------------------------------------------
					// Some elements of the SCVP requests apply to lightweight and batch only
					//---------------------------------------------------------------------------------------------------------
					// Confirm the fullRequest is not present in the requestRef (may be absent or with hash)
					RequestReference rr = cvResponse.getRequestRef();
					if (null != rr && rr.isfullRequest()) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Found full request in CVResponse");
					}

					// Confirm the validation policy is included by reference (not value)
					ValidationPolicy vp = cvResponse.getResponseValidationPolicy();
					if (null == vp) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found ValidationPolicy");
					} else {
						if (null != vp.getValidationAlg()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found ValidationAlg field populated by value");
						}
						if (null != vp.getExtendedKeyUsages()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found ExtendedKeyUsages field populated by value");
						}
						if (null != vp.getInhibitAnyPolicy()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found InhibitAnyPolicy field populated by value");
						}
						if (null != vp.getInhibitPolicyMapping()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found InhibitPolicyMapping field populated by value");
						}
						if (null != vp.getKeyUsages()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found KeyUsages field populated by value");
						}
						if (null != vp.getRequireExplicitPolicy()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found RequireExplicitPolicy field populated by value");
						}
						if (null != vp.getSpecifiedKeyUsages()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found SpecifiedKeyUsages field populated by value");
						}
						if (null != vp.getTrustAnchors()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found TrustAnchors field populated by value");
						}
						if (null != vp.getUserPolicySet()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by reference but found UserPolicySet field populated by value");
						}
					}
				}
				if (client.scvp_profile.equals("lightweight")) {
					//---------------------------------------------------------------------------------------------------------
					// No elements of the SCVP requests apply to lightweight only, so nothing to do here
					//---------------------------------------------------------------------------------------------------------
				}
				if (client.scvp_profile.equals("long-term-record")) {
					//---------------------------------------------------------------------------------------------------------
					// Some elements of the SCVP requests apply to long-term-record only
					//---------------------------------------------------------------------------------------------------------

					// Confirm the fullRequest is present in the requestRef
					RequestReference rr = cvResponse.getRequestRef();
					if (null == rr || !rr.isfullRequest()) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected to find full request in CVResponse but did not");
					}

					// Confirm the validation policy is included by value
					ValidationPolicy vp = cvResponse.getResponseValidationPolicy();
					if (null != vp) {
						if (null == vp.getValidationAlg() &&
								null == vp.getExtendedKeyUsages() && null == vp.getInhibitAnyPolicy() &&
								null == vp.getInhibitPolicyMapping() && null == vp.getKeyUsages() &&
								null == vp.getRequireExplicitPolicy() && null == vp.getSpecifiedKeyUsages() &&
								null == vp.getTrustAnchors() && null == vp.getUserPolicySet()) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Expected to find ValidationPolicy expressed by value but found no fields specified");
						}
					} else {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected to find ValidationPolicy expressed by value but found no ValidationPolicy at all");
					}

					// Confirm respNonce is present (and matches the request nonce)
					ASN1OctetString n = cvResponse.getRespNonce();
					if (null == n) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected to find Nonce in CVResponse but did not");
					}

					// Confirm requestorText is present (and matches what was sent)
					ASN1OctetString rt = cvResponse.getRequestorText();
					if (null == rt) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected to find requestor text in CVResponse but did not");
					}

				}
				if (client.scvp_profile.equals("batch")) {
					//---------------------------------------------------------------------------------------------------------
					// Some elements of the SCVP requests apply to batch only
					//---------------------------------------------------------------------------------------------------------

					// The request will have had exactly X certificate references, so the response should have exactly X
					// certificate replies. The spec is somewhat vague but section 4 states the following:
					//		"The replyObjects item MUST contain exactly one CertReply item for each certificate requested."
					List<CertReply> replyObjects = cvResponse.getReplyObjects();

					if (replyObjects.size() != endEntityCerts.size()) {
						passed_profile_checks = false;
						LOG_CLIENT.error("Expected to find " + Integer.toString(endEntityCerts.size()) + " ReplyObjects but found " + Integer.toString(replyObjects.size()));
					}

					// The wantBacks field should be absent
					for (CertReply certReply : replyObjects) {
						ReplyChecks replyChecks = certReply.getReplyChecks();
						ReplyCheck[] replyChecksValues = replyChecks.getReplyChecks();

						ReplyWantBacks rwb = certReply.getReplyWantBacks();
						if (null != rwb && null != rwb.getReplyWantBackOIDs() && 0 != rwb.getReplyWantBackOIDs().length) {
							passed_profile_checks = false;
							LOG_CLIENT.error("Found WantBack(s) where no WantBacks were expected");
						}
					}
				}
			}
			catch(Exception e)
			{
				LOG_CLIENT.error("Unexpected exception while performing profile checks: ", e);
				valCheck = "unknown";
				passed_profile_checks = false;
			}
		}//end else (profile checks)

		String proCheck = "passed";
		if(!passed_profile_checks) {
			proCheck = "failed";
		}

		if(!"passed".equals(valCheck))
		{
			LOG_VALIDATION_FAILURES.info("java -jar " + jarName + " " + params);
		}

		if(!passed_profile_checks)
		{
			LOG_PROFILE_FAILURES.info("java -jar " + jarName + " " + params);
		}

		LOG_RESULTS.info(new ObjectArrayMessage(client.timestamp, client.test_case_name, target, client.expectSuccess, valCheck, proCheck));
		LOG_CLIENT.info("Finished test case " + client.test_case_name + " in " + (System.currentTimeMillis() - start) + " milliseconds: " + valCheck + "/" + proCheck);
	}

	//--------------------------------------------------------------------------------------------------------------
	// region Things relocated from old DataUtil class
	//--------------------------------------------------------------------------------------------------------------
	private static final String numbers = "0123456789ABCDEF";

	/**
	 * Convert a byte array to a Hex String
	 *
	 * The following method converts a byte[] object to a String object, where
	 * the only output characters are "0123456789ABCDEF".
	 *
	 * @param ba
	 *            A byte array

	 * @return String Hexidecimal String object which represents the contents of
	 *         the byte array */
	public static String byteArrayToString(byte[] ba) {
		if (ba == null) {
			return "";
		}
		StringBuffer hex = new StringBuffer(ba.length * 2);
		for (int i = 0; i < ba.length; i++) {
			hex.append(Integer.toString((ba[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return hex.toString().toUpperCase(Locale.US);
	}

	/**
	 * Method byteArrayToUUID.
	 * @param uuidBytes byte[]
	 * @return UUID
	 */
	public static UUID byteArrayToUUID(byte[] uuidBytes) {
		// uuidBytes is expected to be 16 bytes long
		byte[] ba_msb = new byte[8];
		System.arraycopy(uuidBytes, 0, ba_msb, 0, 8);
		byte[] ba_lsb = new byte[8];
		System.arraycopy(uuidBytes, 8, ba_lsb, 0, 8);
		BigInteger msb = new BigInteger(ba_msb);
		BigInteger lsb = new BigInteger(ba_lsb);
		return new UUID(msb.longValue(), lsb.longValue());
	}

	/**
	 * Convert a byte to a Hex String
	 *
	 * The following method converts a byte[] object to a String object, where
	 * the only output characters are "0123456789ABCDEF".
	 *
	 * @param ba
	 *            A single byte

	 * @return String Hexidecimal String object which represents the contents of
	 *         the byte */
	public static String byteToString(byte ba) {
		byte[] nba = { ba };
		return byteArrayToString(nba);
	}

	/**
	 * Method dateToString.
	 * @param date Date
	 * @return String
	 */
	public static String dateToString(Date date) {
		Calendar expireCa = new GregorianCalendar();
		// Use the incoming Date object to set the Year, Month, and Day
		expireCa.setTime(date);

		int year = expireCa.get(Calendar.YEAR);
		int month = expireCa.get(Calendar.MONTH);
		int day = expireCa.get(Calendar.DAY_OF_MONTH);

		StringBuffer sb = new StringBuffer();
		// I think we can trust we are working with 4 digit years
		sb.append(year);
		// Increment the month due to Jan = 0 with Calendar.MONTH
		month++;
		// Zeropad Month if needed
		if (month < 10) {
			sb.append('0');
		}
		sb.append(month);
		// Zeropad Day if needed
		if (day < 10) {
			sb.append('0');
		}
		sb.append(day);
		return sb.toString();
	}

	/**
	 * Convert a large byte array into multiple smaller byte arrays, with the
	 * output size determined by the caller
	 *
	 * @param inputArray
	 *            An array of bytes
	 * @param arraySize
	 *            The size of each array object returned in the Enumeration
	 * @param zeroPad
	 *            Add a padding of zeros if the last array returned is shorter
	 *            than arraySize

	 * @return Enumeration An Enumeration of byte arrays of the size specified
	 *         by the caller */
	public static byte[][] getArrays(byte[] inputArray, int arraySize,
									 boolean zeroPad) {
		byte[][] tdba = new byte[(int) Math.ceil(inputArray.length
				/ (double) arraySize)][arraySize];
		int start = 0;
		for (int i = 0; i < tdba.length; i++) {
			if (start + arraySize > inputArray.length) {
				byte[] lastArray;
				if (zeroPad) {
					lastArray = new byte[arraySize];
					java.util.Arrays.fill(lastArray, (byte) 0x00);
				} else {
					lastArray = new byte[inputArray.length - start];
				}
				System.arraycopy(inputArray, start, lastArray, 0,
						inputArray.length - start);
				tdba[i] = lastArray;
			} else {
				System.arraycopy(inputArray, start, tdba[i], 0, arraySize);
			}
			start += arraySize;
		}
		return tdba;
	}

	/**
	 * Method getByteArray.
	 * @param st String
	 * @return byte[]
	 */
	public static byte[] getByteArray(String st) {
		byte[] ba = null;
		try {
			ba = st.getBytes("UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ba;
	}

	/**
	 * Convert a byte array of UTF-8 Characters to String
	 *
	 * The following method converts a byte[] object to a String object, where
	 * the only output characters are "0123456789ABCDEF".
	 *
	 * @param ba
	 *            A single byte

	 * @return String Hexidecimal String object which represents the contents of
	 *         the byte */
	public static String getString(byte[] ba) {
		String baSt = "";
		if (ba == null) {
			return baSt;
		}
		try {
			baSt = new String(ba, "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return baSt;
	}

	/**
	 * Method pad.
	 * @param inputArray byte[]
	 * @param padByte byte
	 * @param paddedArrayLen int
	 * @return byte[]
	 */
	public static byte[] pad(byte[] inputArray, byte padByte, int paddedArrayLen) {
		byte[] padArray = new byte[paddedArrayLen];
		java.util.Arrays.fill(padArray, padByte);
		System.arraycopy(inputArray, 0, padArray, 0, inputArray.length);
		return padArray;
	}

	/**
	 * Convert a Hex String to a byte array
	 *
	 * The following method converts a String object to a byte[] object, where
	 * the only valid input characters is "0123456789ABCDEF".
	 *
	 * @param s
	 *            Hexidecimal String object to convert to a byte array

	 * @return byte[] A byte array */
	public static byte[] stringToByteArray(String s) {
		if (s == null)
			return null;
		byte[] result = new byte[s.length() / 2];
		for (int i = 0; i < s.length(); i += 2) {
			int i1 = numbers.indexOf(s.charAt(i));
			int i2 = numbers.indexOf(s.charAt(i + 1));
			result[i / 2] = (byte) ((i1 << 4) | i2);
		}
		return result;
	}

	/**
	 * Method stringtoDate.
	 * @param date String
	 * @return Date
	 */
	public static Date stringtoDate(String date) {

		Calendar expireCa = new GregorianCalendar();

		int year = Integer.parseInt(date.substring(0, 4));
		int month = (Integer.parseInt(date.substring(4, 6)) - 1);
		int day = Integer.parseInt(date.substring(6, 8));
		expireCa.set(Calendar.YEAR, year);
		expireCa.set(Calendar.MONTH, month);
		expireCa.set(Calendar.DAY_OF_MONTH, day);

		// We set the remainder of the fields to Zero since the CHUID is only
		// "YYYYMMDD"
		expireCa.set(Calendar.HOUR, 0);
		expireCa.set(Calendar.HOUR_OF_DAY, 0);
		expireCa.set(Calendar.MINUTE, 0);
		expireCa.set(Calendar.SECOND, 0);
		expireCa.set(Calendar.MILLISECOND, 0);

		return expireCa.getTime();
	}

	/**
	 * Method uuidToByteArray.
	 * @param id UUID
	 * @return byte[]
	 */
	public static byte[] uuidToByteArray(UUID id) {
		ByteBuffer buffer = ByteBuffer.allocate(16);
		buffer.putLong(id.getMostSignificantBits());
		buffer.putLong(id.getLeastSignificantBits());
		return buffer.array();
	}

	/**
	 * XOR two byte arrays
	 *
	 * The following method is used to XOR two byte array objects
	 *
	 * @param array1
	 *            A byte array
	 * @param array2
	 *            A byte array

	 * @return byte[] The result of array1^array2 */
	public static byte[] XOR(byte[] array1, byte[] array2) {
		byte[] result = new byte[array1.length];
		for (int i = 0; i < array1.length; i++) {
			result[i] = (byte) (array1[i] ^ array2[i]);
		}
		return result;
	}
	//--------------------------------------------------------------------------------------------------------------
	// endregion
	//--------------------------------------------------------------------------------------------------------------
}
