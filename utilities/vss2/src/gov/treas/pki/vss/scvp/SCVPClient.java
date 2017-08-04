package gov.treas.pki.vss.scvp;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import gov.treas.pki.vss.crypto.DigestEngine;
import gov.treas.pki.vss.scvp.asn1.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfoParser;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import gov.treas.pki.httpclient.HttpClient;
import gov.treas.pki.httpclient.HttpClientException;
import gov.treas.pki.vss.properties.VSSGlobalProperties;
import gov.treas.pki.vss.rest.json.InvalidityReason;
import gov.treas.pki.vss.rest.json.OCSPResponseList;
import gov.treas.pki.vss.rest.json.ResultByCertificate;
import gov.treas.pki.vss.rest.json.ResultByCertificateData;
import gov.treas.pki.vss.rest.json.SANValue;
import gov.treas.pki.vss.rest.json.TransactionResult;
import gov.treas.pki.vss.rest.json.VSSResponse;
import gov.treas.pki.vss.rest.json.ValidationFailureData;
import gov.treas.pki.vss.rest.json.ValidationResult;
import gov.treas.pki.vss.rest.json.ValidationSuccessData;
import gov.treas.pki.vss.rest.json.WantBackTypeToken;
import gov.treas.pki.vss.rest.json.X509CertificateList;
import gov.treas.pki.vss.status.Status;
import gov.treas.pki.vss.x509.X509Util;

/**
 * @author tejohnson
 * @version $Revision: 1.0 $
 */
public class SCVPClient {

	//--------------------------------------------------------------------------------------------------------------
	//region CustomParametersAndResults class
	//--------------------------------------------------------------------------------------------------------------
	/**
	 * The CustomParametersAndResults class is used by the TestProgramSCVPClient to set path validation algorithm
	 * inputs, to govern some SCVP request elements and to collect request and response data for post-mortem analysis.
	 */
	static class CustomParametersAndResults
	{
		// custom parameters
		private List<String> userPolicySet = null;
		private boolean inhibitAnyPolicy = false;
		private boolean inhibitPolicyMapping = false;
		private boolean requireExplicitPolicy = false;
		private ResponseFlags responseFlags = null;
		private List<Certificate> trustAnchors = null;
		private int nonceSize = 0;
		private String requestorText = null;

		//results
		private byte[] fullRequest = null;
		private byte[] fullResponse = null;

		//parsed results
		private CVResponse cvResponse = null;
		private CMSSignedData cms = null;

		public List<String> getUserPolicySet() {
			return userPolicySet;
		}

		public void setUserPolicySet(List<String> userPolicySet) {
			this.userPolicySet = userPolicySet;
		}

		public boolean getInhibitAnyPolicy() {
			return inhibitAnyPolicy;
		}

		public void setInhibitAnyPolicy(boolean inhibitAnyPolicy) {
			this.inhibitAnyPolicy = inhibitAnyPolicy;
		}

		public boolean getInhibitPolicyMapping() {
			return inhibitPolicyMapping;
		}

		public void setInhibitPolicyMapping(boolean inhibitPolicyMapping) {
			this.inhibitPolicyMapping = inhibitPolicyMapping;
		}

		public boolean getRequireExplicitPolicy() {
			return requireExplicitPolicy;
		}

		public void setRequireExplicitPolicy(boolean requireExplicitPolicy) {
			this.requireExplicitPolicy = requireExplicitPolicy;
		}

		public ResponseFlags getResponseFlags() {
			return responseFlags;
		}

		public void setResponseFlags(ResponseFlags responseFlags) {
			this.responseFlags = responseFlags;
		}

		public List<Certificate> getTrustAnchors() {
			return trustAnchors;
		}

		public void setTrustAnchors(List<Certificate> trustAnchors) {
			this.trustAnchors = trustAnchors;
		}

		public byte[] getFullRequest() {
			return fullRequest;
		}

		public void setFullRequest(byte[] fullRequest) {
			this.fullRequest = fullRequest;
		}

		public byte[] getFullResponse() {
			return fullResponse;
		}

		public void setFullResponse(byte[] fullResponse) {
			this.fullResponse = fullResponse;
		}

		public String getRequestorText() {
			return requestorText;
		}

		public void setRequestorText(String requestorText) {
			this.requestorText = requestorText;
		}

		public int getNonceSize() {
			return nonceSize;
		}

		public void setNonceSize(int nonceSize) {
			this.nonceSize = nonceSize;
		}

		public CVResponse getCvResponse() {
			return cvResponse;
		}

		public void setCvResponse(CVResponse cvResponse) {
			this.cvResponse = cvResponse;
		}

		public CMSSignedData getCms() {
			return cms;
		}

		public void setCms(CMSSignedData cms) {
			this.cms = cms;
		}
	}
	//--------------------------------------------------------------------------------------------------------------
	//endregion
	//--------------------------------------------------------------------------------------------------------------

	//--------------------------------------------------------------------------------------------------------------
	//region SCVPClient member variables
	//--------------------------------------------------------------------------------------------------------------
	/**
	 * Field LOG.
	 */
	private final Logger LOG = LogManager.getLogger(SCVPClient.class);

	/**
	 * Field vssGP
	 */
	private VSSGlobalProperties vssGP = null;

	private Provider jceProvider = null;
	//--------------------------------------------------------------------------------------------------------------
	//endregion
	//--------------------------------------------------------------------------------------------------------------

	//--------------------------------------------------------------------------------------------------------------
	//region Methods added to support perceived TestProgramSCVP needs (other than additional validate variants)
	//--------------------------------------------------------------------------------------------------------------
	private X509Certificate getCertificateFromMapGivenCertReply(Map<String,X509Certificate> certMap, CertReply cr)
	{
		CertReference c = cr.getCertReference();
		if(null == c) {
			return null;
		}
		PKCReference pr = c.getPkc();
		if(null == pr) {
			return null;
		}
		String sha1Hex = "";
		Certificate cert = pr.getCert();
		if(null == cert) {
			SCVPCertID sci = pr.getScvpCertId();
			if(null == sci) {
				return null;
			}
			ASN1OctetString hash = sci.getCertHash();
			byte[] ba = hash.getOctets();
			sha1Hex = Hex.encodeHexString(ba);
		}
		else {
			try {
				byte[] encCert = cert.getEncoded();
				byte[] sha1 = DigestEngine.sHA1Sum(encCert);
				sha1Hex = Hex.encodeHexString(sha1);
			}
			catch(Exception e) {
				return null;
			}
		}
		if(certMap.containsKey(sha1Hex))
		{
			return certMap.get(sha1Hex);
		}
		return null;
	}
	//--------------------------------------------------------------------------------------------------------------
	//endregion
	//--------------------------------------------------------------------------------------------------------------

	public ASN1OctetString generateNonce(int nonceSize) {
		SecureRandom random = null;
		byte[] nonce = null;
		nonce = new byte[nonceSize];
		random = new SecureRandom();
		random.nextBytes(nonce);
		return new DEROctetString(nonce);
	}

	public ValPolResponse getServerPolicy() {
		Status status = Status.getInstance();
		HttpClient client = HttpClient.getInstance();
		VSSGlobalProperties vssGP = VSSGlobalProperties.getInstance();
		/*
		 * Send a Server Policy Request to the SCVP Service
		 */
		ValPolRequest policyRequest = new ValPolRequest(generateNonce(16));
		ServerPolicyRequest encapReq = new ServerPolicyRequest(policyRequest);
		byte[] rawReq = null;
		try {
			rawReq = encapReq.toASN1Primitive().getEncoded();
		} catch (IOException e) {
			LOG.error("Failed to encode Server Policy Request");
		}

		byte[] resBytes = null;
		try {
			resBytes = client.postRequest(vssGP.getScvpServerURI(), rawReq, HttpClient.MIME_VP_REQUEST,
					HttpClient.MIME_VP_RESPONSE);
		} catch (HttpClientException e) {
			LOG.error("Error communicating with SCVP Service for a Policy Request", e);
		}
		/*
		 * Check to see if our response is null, or a ContentInfo
		 */
		CMSSignedData cms = null;
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
				status.serviceFail();
				LOG.error("Error parsing the SCVP Response bytes", e);
			}
			if (object instanceof ASN1SequenceParser) {
				seqPar = (ASN1SequenceParser) object;
				try {
					contentInfoParser = new ContentInfoParser(seqPar);
				} catch (IOException e) {
					status.serviceFail();
					LOG.error("Error parsing the SCVP Response ContentInfo", e);
				}
				if (null != contentInfoParser) {
					contentType = contentInfoParser.getContentType();
					if (CMSObjectIdentifiers.signedData.equals(contentType)) {
						try {
							cms = new CMSSignedData(resBytes);
						} catch (CMSException e) {
							status.serviceFail();
							LOG.error("Error parsing CMS Signed Data", e);
						}
						if (null != cms) {
							if (cms.getSignedContentTypeOID().equals(ValPolResponse.idCtScvpvalPolResponse.getId())) {
								CMSTypedData signedData = cms.getSignedContent();
								object = signedData.getContent();
								if (object instanceof byte[]) {
									try {
										vpResponse = ValPolResponse.getInstance((byte[]) object);
									} catch (IllegalArgumentException e) {
										status.serviceFail();
										LOG.error("Error parsing ValPolResponse", e);
									}
								} else {
									status.serviceFail();
									LOG.error("Error parsing CMS Signed Content");
								}
							} else {
								status.serviceFail();
								LOG.error("CMS Signed Content is not a CVResponse");
							}
						}
					} else if (ValPolResponse.idCtScvpvalPolResponse.equals(contentType)) {
						/*
						 * Unsigned response
						 */
						try {
							vpResponse = ValPolResponse
									.getInstance(contentInfoParser.getContent(0).toASN1Primitive().getEncoded());
						} catch (IOException e) {
							status.serviceFail();
							LOG.error("Error parsing unsigned ValPolResponse");
						}
					} else {
						status.serviceFail();
						LOG.error("Response was not CMS Signed Data or ValPolResponse");
					}
				}
			} else {
				status.serviceFail();
				LOG.error("Error parsing the SCVP Response as a SEQUENCE");
			}
		} else {
			status.serviceFail();
			LOG.error("SCVP Response was NULL");
		}
		if (null != vpResponse) {
			status.markServiceAvailable();
			return vpResponse;
		} else {
			status.serviceFail();
			return null;
		}

	}

	/**
	 * This method (and comments) are the original validate variant before modifications were made to accommodate the
	 * perceived needs of the TestProgramSCVPClient.
	 *
	 * Previous versions of this code performed DPV by overriding the default
	 * validation policy. This code seeks to merely provide middleware to the
	 * SCVP service, through protocol translation. This allows for new endpoints
	 * to be dynamically requested based on the SCVP policies configured within
	 * the SCVP service, without having to alter this code to add a new
	 * endpoint.
	 * 
	 * This client performs DPV requests according to the Treasury SCVP profile,
	 * and includes the SCVP request and response, along with a simple
	 * translation of the response, in a JSON message.
	 * 
	 * All that is needed for the request is the Validation Policy Reference,
	 * the End Entity Certificate that is being validated, the web service URI,
	 * and and the web service client IP address. These are runtime variables
	 * that are used with our SCVP client.
	 * 
	 * @param validationPolRef
	 *            String
	 * @param endEntityCert
	 *            X509Certificate
	 * @param serviceURI
	 *            String
	 * @param serviceClientIP
	 *            String
	 * @return ValidationResponse
	 */
	public VSSResponse validate(X509Certificate endEntityCert, ASN1ObjectIdentifier validationPolRef,
			List<WantBackTypeToken> wantBackList, VSSResponse result) {
		ArrayList<X509Certificate> endEntityCerts = new ArrayList<X509Certificate>();
		endEntityCerts.add(endEntityCert);
		return validate(endEntityCerts, validationPolRef, wantBackList, null, result);
	}

	/**
	 * This validate variant is defined for sake of completeness to address hypothetical users who want to perform
	 * a "batch" request without providing a CustomParametersAndResults reference. It simply calls the actual validate
	 * function with a null parameter for the cp parameter.
	 *
	 * @param endEntityCerts
	 * @param validationPolRef
	 * @param wantBackList
	 * @param result
	 * @return
	 */
	public VSSResponse validate(List<X509Certificate> endEntityCerts, ASN1ObjectIdentifier validationPolRef,
								List<WantBackTypeToken> wantBackList, VSSResponse result) {
		return validate(endEntityCerts, validationPolRef, wantBackList, null, result);
	}

	/**
	 * This validate variant is defined for sake of completeness to address hypothetical users who want to perform a
	 * single certificate request while providing a CustomParametersAndResults instance. It calls the actual validate
	 * function after creating a List of certificates containing on the endEntityCert parameter.
	 *
	 * @param endEntityCert
	 * @param validationPolRef
	 * @param wantBackList
	 * @param cp
	 * @param result
	 * @return
	 */
	public VSSResponse validate(X509Certificate endEntityCert, ASN1ObjectIdentifier validationPolRef,
								List<WantBackTypeToken> wantBackList, CustomParametersAndResults cp, VSSResponse result) {
		ArrayList<X509Certificate> endEntityCerts = new ArrayList<X509Certificate>();
		endEntityCerts.add(endEntityCert);
		return validate(endEntityCerts, validationPolRef, wantBackList, null, result);
	}

	/**
	 * This validate variant does all of the work (the other three are just pass through functions). This implementation
	 * is an adapation of the original SCVP client code that supports using the values from the
	 * CustomParametersAndResults parameter to alter the SCVP request contents. It has also been modified to support
	 * generating "batch" requests and returns the full request and response via the cp parameter for post-mortem
	 * analysis, if desired.
	 *
	 * @param endEntityCerts
	 * @param validationPolRef
	 * @param wantBackList
	 * @param cp
	 * @param result
	 * @return
	 */
	public VSSResponse validate(List<X509Certificate> endEntityCerts, ASN1ObjectIdentifier validationPolRef,
				List<WantBackTypeToken> wantBackList, CustomParametersAndResults cp, VSSResponse result) {

		//Get the properties needed for the SCVP service
		vssGP = VSSGlobalProperties.getInstance();

		/*
		 * The intent is to change the provider for the cryptographic
		 * operations. I.e., a FIPS provider if needed. For now, we will use the
		 * BouncyCastle API since that is what we use for the ASN.1
		 */
		Provider jceProvider = new BouncyCastleProvider();
		Security.addProvider(jceProvider);

		/*
		 * TODO: We can send the SCVP service a ValPolRequest, then we
		 * can look at the response to dynamically configure this client.
		 * 
		 * The results *should* be stored in a singleton instance.
		 * 
		 * I.e., we can restrict sending requests to only those SCVP validation
		 * policies that are configured on the server. We can determine the
		 * supported signature methods, and pick from one the server supports &
		 * select an approved algorithm defined by NIST.
		 * 
		 */
		if(!vssGP.isFunctioningAsTestClient()) {
			SCVPServicePolicy policy = SCVPServicePolicy.getInstance();
			if (null == policy.getValPolResponse()) {
				policy.setValPolResponse(this.getServerPolicy());
			}
		}

		/*
		 * TODO: else, are we between this update and last update, and within the skew?
		 * 
		 * If not, then fetch the latest policy.
		 */

		/*
		 * Create the CvRequest
		 * 
		 * We are going to build the request according to the Treasury SCVP
		 * Profile, Section 4.1. “Lightweight” SCVP Client Request
		 * 
		 * <pre>
		 * 1. CVRequest MUST contain cvRequestVersion.
		 *       1. The value of cvRequestVersion MUST be set to 1.
		 * </pre>
		 * 
		 * The default version the SCVPRequestBuilder will set will be "1".
		 */
		SCVPRequestBuilder builder = new SCVPRequestBuilder();

		//Create a map that associates hashes of certificates that will be referenced in the request with the full
		//certificate. This will be used to fetch certificate information to populate VSSResponse information while
		//traversing the list of ReplyObjects in the response.
		Map<String, X509Certificate> certs = new HashMap<String, X509Certificate>();

		//Create an array to receive certificate references
		ArrayList<PKCReference> certRefsToIncludeInRequest = new ArrayList<PKCReference>();
		for(X509Certificate endEntityCert : endEntityCerts) {
			/*
			 * <pre>
			 * 2. queriedCerts MUST contain exactly one CertReferences item
			 *       1. CertReferences MUST contain exactly one pkcRefs item.
			 *             1. pkcRefs MUST contain exactly one PKCReference item.
			 *                   1. PKCReference MUST include the certificate in the cert item.
			 * </pre>
			 */
			Certificate eCert = null;
			try {
				byte[] encCert = endEntityCert.getEncoded();

				// create a Certificate object from the encoded certificate read from the X509Certificate reference
				ByteArrayInputStream bais = new ByteArrayInputStream(encCert);
				ASN1InputStream dis = new ASN1InputStream(bais);
				ASN1Primitive dobj = dis.readObject();
				dis.close();
				eCert = Certificate.getInstance(dobj);

				// create a PKCRefernece containing the Certificate object
				PKCReference pr = new PKCReference(eCert);

				// add the PKCReference to the pile of references
				certRefsToIncludeInRequest.add(pr);

				// generate an ASCII hex representation (without spaces, thank you) of the certificate then store the
				// certificate in the dictionary using the thumbprint as the key.
				byte[] sha1 = DigestEngine.sHA1Sum(encCert);
				String sha1Hex = Hex.encodeHexString(sha1);
				certs.put(sha1Hex, endEntityCert);
			} catch (IOException e) {
				LOG.error("Error adding EE cert to SCVP request, returning SERVICEFAIL", e);
				return serviceFailure("SERVICEFAIL", "Error with Certificate Validation API", result);
			} catch (CertificateEncodingException e) {
				LOG.error("Error adding EE cert to SCVP request, returning SERVICEFAIL", e);
				return serviceFailure("SERVICEFAIL", "Error with Certificate Validation API", result);
			}
		}
		// get the references as an array
		PKCReference[] refArray = new PKCReference[certRefsToIncludeInRequest.size()];
		certRefsToIncludeInRequest.toArray(refArray);

		//then turn the array of PKCReferences into a CertReferences object and pass it to the builder
		CertReferences cr = new CertReferences(refArray);
		builder.setCertReferences(cr);

		/*
		 * <pre>
		 * 3. checks MUST contain exactly one CertChecks item.
		 *       1. CertChecks MUST include the OID 1.3.6.1.5.5.7.17.3 (id-stc-build-status-checked-pkc-path)
		 * </pre>
		 */
		builder.addCertCheck(CertChecks.idStcBuildStatusCheckedPkcPath);

		/*
		 * <pre>
		 * 4. wantBack MAY include one or more WantBack OIDs.
		 * </pre>
		 * 
		 * wantBack is set with one or more WantBack OIDs depending on the request JSON
		 */
		if(null != wantBackList) {
			ASN1EncodableVector oids = new ASN1EncodableVector();
			for (WantBackTypeToken wantBack : wantBackList) {
				if (wantBack.wantBackTypeToken.equals("certPath")) {
					oids.add(WantBack.idSwbPkcBestCertPath);
				}
				if (wantBack.wantBackTypeToken.equals("revocationInfo")) {
					oids.add(WantBack.idSwbPkcRevocationInfo);
				}
			}
			WantBack wb = WantBack.getInstance(new DERSequence(oids));
			builder.setWantBack(wb);
		}
		/*
		 * <pre>
		 * 5. validationAlg SHOULD contain exactly one ValidationAlg.
		 *       1. ValidationAlg MUST include valAlgId.
		 *             1.The value of valAlgId MUST be set to the id-svp-basicValAlg OID.
		 * </pre>
		 */
		builder.setValidationAlg(new ValidationAlg(ValidationAlg.idSvpBasicValAlg, null));

		/*
		 * <pre>
		 * 6. responseFlags SHOULD include the following ResponseFlags:
		 *       1. fullRequestInResponse
		 *             1.The flag value MUST be set to FALSE.
		 *       2. responseValidationPolByRef
		 *             1.The flag value MUST be set to TRUE.
		 *       3. protectResponse
		 *             1.The flag MUST be set to TRUE.
		 *       4. cachedResponse
		 *             1.The flag MUST be set to TRUE.
		 * </pre>
		 */
		if(null == cp) {
			boolean fullRequestInResponse = false;
			boolean responseValidationPolByRef = true;
			boolean protectResponse = true;
			boolean cachedResponse = true;
			ResponseFlags responseFlags = new ResponseFlags(fullRequestInResponse, responseValidationPolByRef, protectResponse, cachedResponse);
			builder.setResponseFlags(responseFlags);
		}
		else {
			ResponseFlags responseFlags = cp.getResponseFlags();
			if(null != responseFlags) {
				builder.setResponseFlags(responseFlags);
			}
			if(cp.getInhibitAnyPolicy()) {
				builder.setInhibitAnyPolicy(true);
			}
			if(cp.getInhibitPolicyMapping()) {
				builder.setInhibitPolicyMapping(true);
			}
			if(cp.getRequireExplicitPolicy()) {
				builder.setRequireExplicitPolicy(true);
			}
			List<String> userPolicySet = cp.getUserPolicySet();
			if(null != userPolicySet) {
				for(String p:userPolicySet)	{
					builder.addUserPolicy(new ASN1ObjectIdentifier(p));
				}
			}
			if(null != cp.getTrustAnchors()) {
				List<Certificate> tas = cp.getTrustAnchors();
				for(Certificate ta : tas) {
					builder.addTrustAnchor(ta);
				}
			}
		}
		/*
		 * <pre>
		 * 7. revInfos MUST be omitted.
		 * 
		 * 8. producedAt MUST be omitted.
		 * 
		 * 9. requestNonce MUST be omitted.
		 * </pre>
		 * 
		 * These items are omitted.
		 */

		/*
		 * <pre>
		 * 10. ValidationPolicy MUST include exactly one ValidationPolRef.
		 *       1. The valPolId MUST specify one of the policy OIDs defined in 
		 *          this profile, and valPolParams MUST be null.
		 * </pre>
		 * 
		 * The validation policy is based on the request JSON
		 */
		builder.setValidationPolRef(validationPolRef, null);

		/*
		 * 11. requestorText MUST be omitted.
		 */

		/*
		 * Add requestorName (URI SANValue Syntax)
		 */
		builder.setRequestorName(vssGP.getRequestorNameUri());

		if(null != cp.getRequestorText()) {
			builder.setRequestorText(cp.getRequestorText());
		}
		if(0 != cp.getNonceSize())
		{
			builder.generateNonce(cp.getNonceSize());
		}

		/*
		 * Final assembly of the request.
		 */
		SCVPRequest scvpRequest = builder.buildRequest();
		/*
		 * Extract the encoded CVRequest for response validation
		 */
		CVRequest cvRequest = scvpRequest.getRequest();
		byte[] rawReq;
		try {
			rawReq = scvpRequest.toASN1Primitive().getEncoded();
		} catch (IOException e) {
			LOG.error("Error encoding SCVP request, returning SERVICEFAIL", e);
			return serviceFailure("SERVICEFAIL", "Error with Certificate Validation API", result);
		}

		if(null != cp)
		{
			cp.setFullRequest(rawReq);
		}

		/*
		 * Send the request via HTTP/HTTPS
		 */
		HttpClient client = HttpClient.getInstance();
		byte[] resBytes = null;
		try {
			resBytes = client.postRequest(vssGP.getScvpServerURI(), rawReq, HttpClient.MIME_CV_REQUEST, HttpClient.MIME_CV_RESPONSE);
		} catch (HttpClientException e) {
			LOG.error("Error communicating with SCVP Service, returning SERVICEFAIL", e);
			return serviceFailure("SERVICEFAIL", "Error communicating with SCVP Service", result);
		}

		if(null != cp)
		{
			cp.setFullResponse(resBytes);
		}

		/*
		 * Check to see if our response is null, or a ContentInfo
		 */
		CMSSignedData cms = null;
		CVResponse cvResponse = null;
		ContentInfoParser contentInfoParser = null;
		if (resBytes != null) {
			ASN1SequenceParser seqPar = null;
			ASN1ObjectIdentifier contentType = null;
			ASN1StreamParser streamParser = new ASN1StreamParser(resBytes);
			Object object;
			try {
				object = streamParser.readObject();
			} catch (IOException e) {
				LOG.error("Error parsing the SCVP Response bytes, returning SERVICEFAIL", e);
				return serviceFailure("SERVICEFAIL", "Error parsing the SCVP Response bytes", result);
			}
			if (object instanceof ASN1SequenceParser) {
				seqPar = (ASN1SequenceParser) object;
				try {
					contentInfoParser = new ContentInfoParser(seqPar);
				} catch (IOException e) {
					LOG.error("Error parsing the SCVP Response ContentInfo, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error parsing the SCVP Response ContentInfo", result);
				}
				contentType = contentInfoParser.getContentType();
				if (CMSObjectIdentifiers.signedData.equals(contentType)) {
					try {
						cms = new CMSSignedData(resBytes);
					} catch (CMSException e) {
						LOG.error("Error parsing CMS Signed Data, returning SERVICEFAIL", e);
						return serviceFailure("SERVICEFAIL", "Error parsing CMS Signed Data", result);
					}
					if (cms.getSignedContentTypeOID().equals(CVResponse.idCtScvpCertValResponse.getId())) {
						CMSTypedData signedData = cms.getSignedContent();
						object = signedData.getContent();
						if (object instanceof byte[]) {
							try {
								cvResponse = CVResponse.getInstance((byte[])object);

								if(null != cp)
								{
									cp.setCvResponse(cvResponse);
									cp.setCms(cms);
								}
							} catch (IllegalArgumentException e) {
								LOG.error("Error parsing CVResponse, returning SERVICEFAIL", e);
								return serviceFailure("SERVICEFAIL", "Error parsing CVResponse", result);
							}
						} else {
							LOG.error("Error parsing CMS Signed Content, returning SERVICEFAIL");
							return serviceFailure("SERVICEFAIL", "Error parsing CMS Signed Content", result);
						}
					} else {
						LOG.error("CMS Signed Content is not a CVResponse, returning SERVICEFAIL");
						return serviceFailure("SERVICEFAIL", "CMS Signed Content is not a CVResponse", result);
					}
				} else if (CVResponse.idCtScvpCertValResponse.equals(contentType)) {
					/*
					 * Unsigned response
					 */
					try {
						cvResponse = CVResponse.getInstance(contentInfoParser.getContent(0).toASN1Primitive().getEncoded());

						if(null != cp)
						{
							cp.setCvResponse(cvResponse);
							cp.setCms(null);
						}
					} catch (IOException e) {
						LOG.error("Error parsing unsigned CVResponse, returning SERVICEFAIL");
						return serviceFailure("SERVICEFAIL", "Error parsing unsigned CVResponse", result);
					}
				} else {
					LOG.error("Response was not CMS Signed Data or CVResponse, returning SERVICEFAIL");
					return serviceFailure("SERVICEFAIL", "Response was not CMS Signed Data or CVResponse", result);
				}
			} else {
				LOG.error("Error parsing the SCVP Response as a SEQUENCE, returning SERVICEFAIL");
				return serviceFailure("SERVICEFAIL", "Error parsing the SCVP Response as a SEQUENCE", result);
			}
		} else {
			LOG.error("SCVP Response was NULL, returning SERVICEFAIL");
			return serviceFailure("SERVICEFAIL", "SCVP Response was NULL", result);
		}

		if (null != cvResponse) {
			if (null != cms) {
				/*
				 * Verify Signed Response
				 */
				X509Certificate issuer = vssGP.getSCVPSignerIsser();
				if(null == issuer)
				{
					LOG.error("Failed to retrieve certificate needed to validate the SCVP Response, returning SERVICEFAIL");
					return serviceFailure("SERVICEFAIL", "Failed to retrieve certificate needed to validate the SCVP Response", result);
				}
				PublicKey issuerSigner = issuer.getPublicKey();
				try {
					SCVPResponseValidator.verifyResponse(cms, issuerSigner, cvRequest, cvResponse);
				} catch (InvalidKeyException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (CertificateException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (NoSuchAlgorithmException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (NoSuchProviderException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SignatureException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (CMSException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SCVPVersionException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SCVPRequestReferenceException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SCVPClockSkewException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SCVPNonceException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				}              
			}
			else
			{
				/*
				 * Verify Unprotected Response
				 */
				try {
					SCVPResponseValidator.verifyResponse(cvRequest, cvResponse);
				} catch (SCVPVersionException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SCVPRequestReferenceException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SCVPClockSkewException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				} catch (SCVPNonceException e) {
					LOG.error("Error validating the SCVP Response, returning SERVICEFAIL", e);
					return serviceFailure("SERVICEFAIL", "Error validating the SCVP Response", result);
				}
			}
			/*
			 * Now we will process the response.
			 * 
			 * Check to make sure the CvStatusCode is "okay (0)"
			 */
			CVStatusCode status = cvResponse.getResponseStatus().getStatusCode();

			if (status.getValue().intValue() == CVStatusCode.OKAY) {
				
				/*
				 * We are going to get the CertReply objects. Since we only
				 * include one certificate to check for validation in the
				 * request, there should only be one CertReply that we care
				 * about. Since the CVResponse Status Code is "okay (0)", the
				 * CertReply will not be null.
				 */
				List<CertReply> replyObjects = cvResponse.getReplyObjects();
				//CertReply certReply = replyObjects.get(0);
				for(CertReply certReply : replyObjects) {
					X509Certificate endEntityCert = getCertificateFromMapGivenCertReply(certs, certReply);
					/*
					 * When decoding the certificate contents, don't always assume that the
					 * fields will be non-NULL. For example, cardAuth certs MAY have a NULL
					 * subject name.
					 */
					String x509SubjectName = null;
					if (null != endEntityCert.getSubjectDN()) {
						x509SubjectName = endEntityCert.getSubjectDN().toString();
					}
					String x509IssuerName = null;
					if (null != endEntityCert.getIssuerDN()) {
						x509IssuerName = endEntityCert.getIssuerDN().toString();
					}
					String x509SerialNumber = null;
					if (null != endEntityCert.getSerialNumber()) {
						x509SerialNumber = endEntityCert.getSerialNumber().toString();
					}
					/*
					 * Get subjectAltName values, swallow the exception as far as the
					 * consumer is concerned, but log it.
					 */
					List<SANValue> x509SubjectAltName = null;
					try {
						x509SubjectAltName = X509Util.getSubjectAlternativeNames(endEntityCert);
					} catch (IOException e) {
						LOG.error("Error parsing Certificate SAN.", e);
					}

					/*
					 * Set validationTime and nextUpdate in the response
					 *
					 * Date Format now conforms to ISO 8601:
					 *
					 * http://xkcd.com/1179/
					 */
					String validationTime = null;
					Date valTime = null;
					SimpleDateFormat dFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
					dFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
					try {
						valTime = certReply.getReplyValTime().getDate();
					} catch (ParseException e) {
						LOG.error("Error parsing ReplyValTime from SCVP Response", e);
					}
					validationTime = dFormat.format(valTime);

					/*
					 * Checking for null since some responses will not have
					 * nextUpdate.
					 */
					Date nxtUpdate = null;
					String nextUpdate = null;
					try {
						if (null != certReply.getNextUpdate()) {
							nxtUpdate = certReply.getNextUpdate().getDate();
						}
					} catch (ParseException e) {
						LOG.error("Error parsing NextUpdate from SCVP Response", e);
					}
					if (null != nxtUpdate) {
						nextUpdate = dFormat.format(nxtUpdate);
					}

					/*
					 * Add in the certificate details
					 */
					ResultByCertificateData certResult = new ResultByCertificateData();
					certResult.vssCertId = X509Util.getVssCertId(endEntityCert);
					certResult.x509SubjectName = x509SubjectName;
					certResult.x509IssuerName = x509IssuerName;
					certResult.x509SerialNumber = x509SerialNumber;
					certResult.x509SubjectAltName = x509SubjectAltName;
					certResult.validationTime = validationTime;
					certResult.nextUpdate = nextUpdate;

					/*
					 * Place the resultByCertificate into the overall result. From
					 * here, the results should only ever be updated.
					 */
					ResultByCertificate resultByCertificate = new ResultByCertificate();
					resultByCertificate.resultByCertificate = certResult;

					/*
					 *  private final static String success = new String("Success: All checks were performed successfully");
					 */
					final String malformedPKC = new String("Failure: The public key certificate was malformed");
					final String malformedAC = new String("Failure: The attribute certificate was malformed");
					final String unavailableValidationTime = new String(
							"Failure: Historical data for the requested validation time is not available");
					final String referenceCertHashFail = new String(
							"Failure: The server could not locate the reference certificate or the referenced certificate did not match the hash value provided");
					final String certPathConstructFail = new String(
							"Failure: No certification path could be constructed");
					final String certPathNotValid = new String(
							"Failure: The constructed certification path is not valid with respect to the validation policy");
					final String certPathNotValidNow = new String(
							"Failure: The constructed certification path is not valid with respect to the validation policy, but a query at a later time may be successful");
					final String wantBackUnsatisfied = new String(
							"Failure: All checks were performed successfully; however, one or more of the wantBacks could not be satisfied");

					switch (certReply.getReplyStatus().getValue().intValue()) {
						case ReplyStatus.SUCCESS: {

							/*
							 * Bottom line, if the replyStatus is anything other than
							 * ReplyStatus.success, then the cert is invalid based on
							 * the policy, path discovery, available revocation data,
							 * etc.
							 */
							TransactionResult tResult = new TransactionResult();
							tResult.transactionResultToken = "SUCCESS";
							tResult.transactionResultText = "Validation Operation Completed Successfully";
							result.transactionResult = tResult;
							List<gov.treas.pki.vss.rest.json.WantBack> wantBackResultList = new ArrayList<gov.treas.pki.vss.rest.json.WantBack>();
							ValidationSuccessData successData = new ValidationSuccessData();
							//certResult = result.validationResult.resultsByCertificateList.get(0).resultByCertificate;
							certResult.validationResultToken = "SUCCESS";
					
							/*
							 * Get the reply wantBacks
							 */
							ReplyWantBacks replyWantBacks = certReply.getReplyWantBacks();
							Enumeration<ASN1ObjectIdentifier> rwbOids = replyWantBacks.oids();
							while (rwbOids.hasMoreElements()) {
								ASN1ObjectIdentifier currentOid = rwbOids.nextElement();
								ReplyWantBack replyWantBack = replyWantBacks.getReplyWantBack(currentOid);
								if (currentOid.equals(WantBack.idSwbPkcBestCertPath)) {
									CertificateFactory cf = null;
									try {
										cf = CertificateFactory.getInstance("X.509");
									} catch (CertificateException e) {
										LOG.error("Error decoding certificate from ReplyWantBack", e);
									}
									if (null != cf) {
										ASN1Sequence encapSeq = (ASN1Sequence) replyWantBack.getParsedValue();
										ASN1Encodable[] pathArr = encapSeq.toArray();
										ArrayList<X509Certificate> pathAl = new ArrayList<X509Certificate>();
										for (ASN1Encodable certData : pathArr) {
											byte[] certBytes = null;
											try {
												certBytes = certData.toASN1Primitive().getEncoded();
											} catch (IOException e) {
												LOG.error("Error decoding certificate from ReplyWantBack", e);
											}
											ByteArrayInputStream bais = new ByteArrayInputStream(certBytes);
											try {
												pathAl.add((X509Certificate) cf.generateCertificate(bais));
											} catch (CertificateException e) {
												LOG.error("Error decoding certificate from ReplyWantBack", e);
											}
										}
										List<gov.treas.pki.vss.rest.json.X509Certificate> certList = new ArrayList<gov.treas.pki.vss.rest.json.X509Certificate>();
										for (X509Certificate certificate : pathAl) {
											gov.treas.pki.vss.rest.json.X509Certificate bCert = new gov.treas.pki.vss.rest.json.X509Certificate();
											try {
												bCert.x509Certificate = Base64.encodeBase64String(certificate.getEncoded());
											} catch (CertificateEncodingException e) {
												LOG.error("Error Base64 encoding certificate from ReplyWantBack", e);
											}
											certList.add(bCert);
										}
										X509CertificateList encodedList = new X509CertificateList();
										encodedList.x509CertificateList = certList;
										gov.treas.pki.vss.rest.json.WantBack certPath = new gov.treas.pki.vss.rest.json.WantBack();
										certPath.certPath = encodedList;
										wantBackResultList.add(certPath);
									}
								} else if (currentOid.equals(WantBack.idSwbPkcRevocationInfo)) {
									ASN1Sequence encapSeq = (ASN1Sequence) replyWantBack.getParsedValue();
									RevocationInfos ris = RevocationInfos.getInstance(encapSeq.getObjectAt(0));
									List<gov.treas.pki.vss.rest.json.OCSPResponse> ocspList = new ArrayList<gov.treas.pki.vss.rest.json.OCSPResponse>();
									for (RevocationInfo ri : ris.getRevocationInfos()) {
										if (ri.getTagNo() == RevocationInfo.ocsp) {
											//OCSPResponse ocspResp = OCSPResponse.getInstance(ri.getRevocationObject());
											ASN1Sequence s = (ASN1Sequence)ri.getRevocationObject();
											OCSPResponse ocspResp = OCSPResponse.getInstance(s.getObjectAt(0));
											gov.treas.pki.vss.rest.json.OCSPResponse bOcsp = new gov.treas.pki.vss.rest.json.OCSPResponse();
											try {
												bOcsp.ocspResponse = Base64.encodeBase64String(ocspResp.getEncoded());
											} catch (IOException e) {
												LOG.error("Error Base64 encoding OCSP response from ReplyWantBack", e);
											}
											ocspList.add(bOcsp);
										}
										else if(vssGP.isFunctioningAsTestClient() && (ri.getTagNo() == RevocationInfo.crl || ri.getTagNo() == RevocationInfo.deltaCrl)) {
											//These are not aggregated into the JSON stuff but need not generate noisy output
											//when used in the test program client.
										}
										else {
											LOG.error("Unsupported revocation info in ReplyWantBack: " + ri.getTagNo());
										}
									}
									OCSPResponseList encodedList = new OCSPResponseList();
									encodedList.ocspResponseList = ocspList;
									gov.treas.pki.vss.rest.json.WantBack rInfo = new gov.treas.pki.vss.rest.json.WantBack();
									rInfo.revocationInfo = encodedList;
									wantBackResultList.add(rInfo);
								}
							}
							successData.wantBackResultList = wantBackResultList;
							certResult.validationSuccessData = successData;
							resultByCertificate.resultByCertificate = certResult;

							if(null == result.validationResult) {
								result.validationResult = new ValidationResult();
							}
							result.validationResult.resultsByCertificateList.add(resultByCertificate);

							break;
							//return result;
						}

						/*
						 * To determine why the cert is invalid, we SHOULD have
						 * validationError data for any replyStatus that is 3, 5, 6, 7,
						 * & 8.
						 *
						 * -unavailableValidationTime -certPathConstructFail
						 * -certPathNotValid -certPathNotValidNow -wantBackUnsatisfied
						 *
						 * Otherwise, if there is no validation error, it is more likely
						 * a path discovery error from our check, which is id-stc 3
						 * (id-stc-build-status-checked-pkc-path)
						 */
						case ReplyStatus.MALFORMEDPKC: {
							result = failure(malformedPKC, false, result, certResult);
							break;
						}
						case ReplyStatus.MALFORMEDAC: {
							result = failure(malformedAC, false, result, certResult);
							break;
						}
						case ReplyStatus.UNAVAILABLEVALIDATIONTIME: {
							/*
							 * Process the validationErrors
							 */
							StringBuffer veSb = new StringBuffer();
							veSb.append(unavailableValidationTime);
							ASN1ObjectIdentifier[] errors = certReply.getValidationErrors();

							/*
							 * If we have more detail, add it
							 */
							if (null != errors && errors.length > 0) {
								for (ASN1ObjectIdentifier oid : errors) {
									veSb.append(": ");
									veSb.append(validationErrorString(oid.getId()));
								}
							} else {
								/*
								 * We need to check for path discovery errors since we
								 * are doing id-stc 3
								 * (id-stc-build-status-checked-pkc-path)
								 *
								 * 0: Certificate path valid 1: No valid path 2:
								 * Revocation off-line 3: Revocation unavailable 4: No
								 * known source for revocation information
								 */
								ReplyChecks replyChecks = certReply.getReplyChecks();
								Enumeration<?> rcsEn = replyChecks.getValues();
								while (rcsEn.hasMoreElements()) {
									ReplyCheck replyCheck = null;
									try {
										replyCheck = ReplyCheck.getInstance(rcsEn.nextElement());
									} catch (IOException e) {
										LOG.error("Error parsing ReplyCheck", e);
									}
									if (null != replyCheck) {
										veSb.append(": ");
										veSb.append(certPathNotValidStatus(replyCheck.getStatus()));
									}
								}
							}
							result = failure(veSb.toString(), false, result, certResult);
							break;
						}
						case ReplyStatus.REFERENCECERTHASHFAIL: {
							result = failure(referenceCertHashFail, false, result, certResult);
							break;
						}
						case ReplyStatus.CERTPATHCONSTRUCTFAIL: {
							/*
							 * Process the validationErrors
							 */
							StringBuffer veSb = new StringBuffer();
							veSb.append(certPathConstructFail);
							ASN1ObjectIdentifier[] errors = certReply.getValidationErrors();

							/*
							 * If we have more detail, add it
							 */
							if (null != errors && errors.length > 0) {
								for (ASN1ObjectIdentifier oid : errors) {
									veSb.append(": ");
									veSb.append(validationErrorString(oid.getId()));
								}
							} else {
								/*
								 * We need to check for path discovery errors since we
								 * are doing id-stc 3
								 * (id-stc-build-status-checked-pkc-path)
								 *
								 * 0: Certificate path valid 1: No valid path 2:
								 * Revocation off-line 3: Revocation unavailable 4: No
								 * known source for revocation information
								 */
								ReplyChecks replyChecks = certReply.getReplyChecks();
								Enumeration<?> rcsEn = replyChecks.getValues();
								while (rcsEn.hasMoreElements()) {
									ReplyCheck replyCheck = null;
									try {
										replyCheck = ReplyCheck.getInstance(rcsEn.nextElement());
									} catch (IOException e) {
										LOG.error("Error parsing ReplyCheck", e);
									}
									if (null != replyCheck) {
										veSb.append(": ");
										veSb.append(certPathNotValidStatus(replyCheck.getStatus()));
									}
								}
							}
							result = failure(veSb.toString(), false, result, certResult);
							break;
						}
						case ReplyStatus.CERTPATHNOTVALID: {
							/*
							 * Process the validationErrors
							 */
							StringBuffer veSb = new StringBuffer();
							veSb.append(certPathNotValid);
							ASN1ObjectIdentifier[] errors = certReply.getValidationErrors();
							/*
							 * If we have more detail, add it
							 */
							if (null != errors && errors.length > 0) {
								for (ASN1ObjectIdentifier oid : errors) {
									veSb.append(": ");
									veSb.append(validationErrorString(oid.getId()));
								}
							} else {
								/*
								 * We need to check for path discovery errors since we
								 * are doing id-stc 3
								 * (id-stc-build-status-checked-pkc-path)
								 *
								 * 0: Certificate path valid 1: No valid path 2:
								 * Revocation off-line 3: Revocation unavailable 4: No
								 * known source for revocation information
								 */
								ReplyChecks replyChecks = certReply.getReplyChecks();
								Enumeration<?> rcsEn = replyChecks.getValues();
								while (rcsEn.hasMoreElements()) {
									ReplyCheck replyCheck = null;
									try {
										replyCheck = ReplyCheck.getInstance(rcsEn.nextElement());
									} catch (IOException e) {
										LOG.error("Error parsing ReplyCheck", e);
									}
									if (null != replyCheck) {
										veSb.append(": ");
										veSb.append(certPathNotValidStatus(replyCheck.getStatus()));
									}
								}
							}
							result = failure(veSb.toString(), true, result, certResult);
							break;
						}
						case ReplyStatus.CERTPATHNOTVALIDNOW: {
							/*
							 * Process the validationErrors
							 */
							StringBuffer veSb = new StringBuffer();
							veSb.append(certPathNotValidNow);
							ASN1ObjectIdentifier[] errors = certReply.getValidationErrors();
							/*
							 * If we have more detail, add it.  It would appear that ValidationErrors
							 * may be null for a CERTPATHNOTVALIDNOW ReplyStatus.
							 */
							if (null != errors && errors.length > 0) {
								for (ASN1ObjectIdentifier oid : errors) {
									veSb.append(": ");
									veSb.append(validationErrorString(oid.getId()));
								}
							} else {
								/*
								 * We need to check for path discovery errors since we
								 * are doing id-stc 3
								 * (id-stc-build-status-checked-pkc-path)
								 *
								 * 0: Certificate path valid 1: No valid path 2:
								 * Revocation off-line 3: Revocation unavailable 4: No
								 * known source for revocation information
								 */
								ReplyChecks replyChecks = certReply.getReplyChecks();
								Enumeration<?> rcsEn = replyChecks.getValues();
								while (rcsEn.hasMoreElements()) {
									ReplyCheck replyCheck = null;
									try {
										replyCheck = ReplyCheck.getInstance(rcsEn.nextElement());
									} catch (IOException e) {
										LOG.error("Error parsing ReplyCheck", e);
									}
									if (null != replyCheck) {
										veSb.append(": ");
										veSb.append(certPathNotValidStatus(replyCheck.getStatus()));
									}
								}
							}
							result = failure(veSb.toString(), false, result, certResult);
							break;
						}
						case ReplyStatus.WANTBACKUNSATISFIED: {
							/*
							 * Process the validationErrors
							 */
							StringBuffer veSb = new StringBuffer();
							veSb.append(wantBackUnsatisfied);
							ASN1ObjectIdentifier[] errors = certReply.getValidationErrors();
							/*
							 * If we have more detail, add it
							 */
							if (null != errors && errors.length > 0) {
								for (ASN1ObjectIdentifier oid : errors) {
									veSb.append(": ");
									veSb.append(validationErrorString(oid.getId()));
								}
							} else {
								/*
								 * We need to check for path discovery errors since we
								 * are doing id-stc 3
								 * (id-stc-build-status-checked-pkc-path)
								 *
								 * 0: Certificate path valid 1: No valid path 2:
								 * Revocation off-line 3: Revocation unavailable 4: No
								 * known source for revocation information
								 */
								ReplyChecks replyChecks = certReply.getReplyChecks();
								Enumeration<?> rcsEn = replyChecks.getValues();
								while (rcsEn.hasMoreElements()) {
									ReplyCheck replyCheck = null;
									try {
										replyCheck = ReplyCheck.getInstance(rcsEn.nextElement());
									} catch (IOException e) {
										LOG.error("Error parsing ReplyCheck", e);
									}
									if (null != replyCheck) {
										veSb.append(": ");
										veSb.append(certPathNotValidStatus(replyCheck.getStatus()));
									}
								}
							}
							result = failure(veSb.toString(), false, result, certResult);
							break;
						}
						default: {
							result = failure("Unknown validation error: " + cvResponse.getResponseStatus().getStatusCode().getValue().intValue(), false, result, certResult);
							break;
						}
					}
				}
				return result;
			} else {
				/*
				 * CVStatusCode value meanings
				 * 
				 * The CVStatusCode meaning for "okay (0)" is omitted from this code.
				 */
				final String skipUnrecognizedItems = new String(
						"The request included some unrecognized non-critical extensions; however, processing was able to continue ignoring them.");
				final String tooBusy = new String("Too busy; try again later.");
				final String invalidRequest = new String(
						"The server was able to decode the request, but there was some other problem with the request.");
				final String internalError = new String("An internal server error occurred.");
				final String badStructure = new String("The structure of the request was wrong.");
				final String unsupportedVersion = new String(
						"The version of request is not supported by this server.");
				final String abortUnrecognizedItems = new String(
						"The request included unrecognized items, and the server was not able to continue processing.");
				final String unrecognizedSigKey = new String(
						"The server could not validate the key used to protect the request.");
				final String badSignatureOrMAC = new String(
						"The signature or message authentication code did not match the body of the request.");
				final String unableToDecode = new String("The encoding was not understood.");
				final String notAuthorized = new String("The request was not authorized.");
				final String unsupportedChecks = new String(
						"The request included unsupported checks items, and the server was not able to continue processing.");
				final String unsupportedWantBacks = new String(
						"The request included unsupported wantBack items, and the server was not able to continue processing.");
				final String unsupportedSignatureOrMAC = new String(
						"The server does not support the signature or message authentication code algorithm used by the client to protect the request.");
				final String invalidSignatureOrMAC = new String(
						"The server could not validate the client's signature or message authentication code on the request.");
				final String protectedResponseUnsupported = new String(
						"The server could not generate a protected response as requested by the client.");
				final String unrecognizedResponderName = new String(
						"The server does not have a certificate matching the requested responder name.");
				final String relayingLoop = new String("The request was previously relayed by the same server.");
				final String unrecognizedValPol = new String(
						"The request contained an unrecognized validation policy reference.");
				final String unrecognizedValAlg = new String(
						"The request contained an unrecognized validation algorithm OID.");
				final String fullRequestInResponseUnsupported = new String(
						"The server does not support returning the full request in the response.");
				final String fullPolResponseUnsupported = new String(
						"The server does not support returning the full validation policy by value in the response.");
				final String inhibitPolicyMappingUnsupported = new String(
						"The server does not support the requested value for inhibit policy mapping.");
				final String requireExplicitPolicyUnsupported = new String(
						"The server does not support the requested value for require explicit policy.");
				final String inhibitAnyPolicyUnsupported = new String(
						"The server does not support the requested value for inhibit anyPolicy.");
				final String validationTimeUnsupported = new String(
						"The server only validates requests using current time.");
				final String unrecognizedCritQueryExt = new String(
						"The query item in the request contains a critical extension whose OID is not recognized.");
				final String unrecognizedCritRequestExt = new String(
						"The request contains a critical request extension whose OID is not recognized.");

				/*
				 * Let's get the CVStatusCode, and return better SCVP Error
				 * details to the client.
				 */
				switch (status.getValue().intValue()) {
				case CVStatusCode.SKIPUNRECOGNIZEDITEMS: { // skipUnrecognizedItems (1)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + skipUnrecognizedItems);
					return serviceFailure("SERVICEFAIL", skipUnrecognizedItems, result);
				}
				case CVStatusCode.TOOBUSY: { // tooBusy (10)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + tooBusy);
					return serviceFailure("SERVICEFAIL", tooBusy, result);
				}
				case CVStatusCode.INVALIDREQUEST: { // invalidRequest (11)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + invalidRequest);
					return serviceFailure("SERVICEFAIL", invalidRequest, result);
				}
				case CVStatusCode.INTERNALERROR: { // internalError (12)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + internalError);
					return serviceFailure("SERVICEFAIL", internalError, result);
				}
				case CVStatusCode.BADSTRUCTURE: { // badStructure (20)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + badStructure);
					return serviceFailure("SERVICEFAIL", badStructure, result);
				}
				case CVStatusCode.UNSUPPORTEDVERSION: { // unsupportedVersion (21)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unsupportedVersion);
					return serviceFailure("SERVICEFAIL", unsupportedVersion, result);
				}
				case CVStatusCode.ABORTUNRECOGNIZEDITEMS: { // abortUnrecognizedItems (22)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + abortUnrecognizedItems);
					return serviceFailure("SERVICEFAIL", abortUnrecognizedItems, result);
				}
				case CVStatusCode.UNRECOGNIZEDSIGKEY: { // unrecognizedSigKey (23)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unrecognizedSigKey);
					return serviceFailure("SERVICEFAIL", unrecognizedSigKey, result);
				}
				case CVStatusCode.BADSIGNATUREORMAC: { // badSignatureOrMAC (24)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + badSignatureOrMAC);
					return serviceFailure("SERVICEFAIL", badSignatureOrMAC, result);
				}
				case CVStatusCode.UNABLETODECODE: { // unableToDecode (25)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unableToDecode);
					return serviceFailure("SERVICEFAIL", unableToDecode, result);
				}
				case CVStatusCode.NOTAUTHORIZED: { // notAuthorized (26)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + notAuthorized);
					return serviceFailure("SERVICEFAIL", notAuthorized, result);
				}
				case CVStatusCode.UNSUPPORTEDCHECKS: { // unsupportedChecks (27)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unsupportedChecks);
					return serviceFailure("SERVICEFAIL", unsupportedChecks, result);
				}
				case CVStatusCode.UNSUPPORTEDWANTBACKS: { // unsupportedWantBacks (28)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unsupportedWantBacks);
					return serviceFailure("SERVICEFAIL", unsupportedWantBacks, result);
				}
				case CVStatusCode.UNSUPPORTEDSIGNATUREORMAC: { // unsupportedSignatureOrMAC (29)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unsupportedSignatureOrMAC);
					return serviceFailure("SERVICEFAIL", unsupportedSignatureOrMAC, result);
				}
				case CVStatusCode.INVALIDSIGNATUREORMAC: { // invalidSignatureOrMAC (30)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + invalidSignatureOrMAC);
					return serviceFailure("SERVICEFAIL", invalidSignatureOrMAC, result);
				}
				case CVStatusCode.PROTECTEDRESPONSEUNSUPPORTED: { // protectedResponseUnsupported (31)
					LOG.error(
							"Error received from SCVP server, returning SERVICEFAIL: " + protectedResponseUnsupported);
					return serviceFailure("SERVICEFAIL", protectedResponseUnsupported, result);
				}
				case CVStatusCode.UNRECOGNIZEDRESPONDERNAME: { // unrecognizedResponderName (32)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unrecognizedResponderName);
					return serviceFailure("SERVICEFAIL", unrecognizedResponderName, result);
				}
				case CVStatusCode.RELAYINGLOOP: { // relayingLoop (40)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + relayingLoop);
					return serviceFailure("SERVICEFAIL", relayingLoop, result);
				}
				case CVStatusCode.UNRECOGNIZEDVALPOL: { // unrecognizedValPol (50)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unrecognizedValPol);
					return serviceFailure("SERVICEFAIL", unrecognizedValPol, result);
				}
				case CVStatusCode.UNRECOGNIZEDVALALG: { // unrecognizedValAlg (51)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unrecognizedValAlg);
					return serviceFailure("SERVICEFAIL", unrecognizedValAlg, result);
				}
				case CVStatusCode.FULLREQUESTINRESPONSEUNSUPPORTED: { // fullRequestInResponseUnsupported (52)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: "
							+ fullRequestInResponseUnsupported);
					return serviceFailure("SERVICEFAIL", fullRequestInResponseUnsupported, result);
				}
				case CVStatusCode.FULLPOLRESPONSEUNSUPPORTED: { // fullPolResponseUnsupported (53)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + fullPolResponseUnsupported);
					return serviceFailure("SERVICEFAIL", fullPolResponseUnsupported, result);
				}
				case CVStatusCode.INHIBITPOLICYMAPPINGUNSUPPORTED: { // inhibitPolicyMappingUnsupported (54)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: "
							+ inhibitPolicyMappingUnsupported);
					return serviceFailure("SERVICEFAIL", inhibitPolicyMappingUnsupported, result);
				}
				case CVStatusCode.REQUIREEXPLICITPOLICYUNSUPPORTED: { // requireExplicitPolicyUnsupported (55)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: "
							+ requireExplicitPolicyUnsupported);
					return serviceFailure("SERVICEFAIL", requireExplicitPolicyUnsupported, result);
				}
				case CVStatusCode.INHIBITANYPOLICYUNSUPPORTED: { // inhibitAnyPolicyUnsupported (56)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + inhibitAnyPolicyUnsupported);
					return serviceFailure("SERVICEFAIL", inhibitAnyPolicyUnsupported, result);
				}
				case CVStatusCode.VALIDATIONTIMEUNSUPPORTED: { // validationTimeUnsupported (57)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + validationTimeUnsupported);
					return serviceFailure("SERVICEFAIL", validationTimeUnsupported, result);
				}
				case CVStatusCode.UNRECOGNIZEDCRITQUERYEXT: { // unrecognizedCritQueryExt (63)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unrecognizedCritQueryExt);
					return serviceFailure("SERVICEFAIL", unrecognizedCritQueryExt, result);
				}
				case CVStatusCode.UNRECOGNIZEDCRITREQUESTEXT: { // unrecognizedCritRequestExt (64)
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + unrecognizedCritRequestExt);
					return serviceFailure("SERVICEFAIL", unrecognizedCritRequestExt, result);
				}
				default: {
					LOG.error("Error received from SCVP server, returning SERVICEFAIL: " + "SCVP Error: "
							+ status.toString());
					return serviceFailure("SERVICEFAIL", "SCVP Error: " + status.toString(), result);
				}
				}
			}
		} else {
			LOG.error("Error communicating with SCVP server, null response, returning SERVICEFAIL");
			return serviceFailure("SERVICEFAIL", "SCVPResponse was null", result);
		}
	}

	/*
	 * Get validationErrorString
	 */
	public static String validationErrorString(String string) {
		/*
		 * validationError OIDs
		 */
		final String expired = "1.3.6.1.5.5.7.19.3.1";
		final String notYetValid = "1.3.6.1.5.5.7.19.3.2";
		final String wrongTrustAnchor = "1.3.6.1.5.5.7.19.3.3";
		final String noValidCertPath = "1.3.6.1.5.5.7.19.3.4";
		final String revoked = "1.3.6.1.5.5.7.19.3.5";
		final String invalidKeyPurpose = "1.3.6.1.5.5.7.19.3.9";
		final String invalidKeyUsage = "1.3.6.1.5.5.7.19.3.10";
		final String invalidCertPolicy = "1.3.6.1.5.5.7.19.3.11";
		final String weakCertKey = "1.3.6.1.4.1.2930.6.1.1.1";
		final String weakCertHash = "1.3.6.1.4.1.2930.6.1.1.2";
		/*
		 * validationError OID meanings
		 */
		final String expiredStr = "The validation time used for the request was later than the notAfter time in the end certificate: Certificate is expired";
		final String notYetValidStr = "The validation time used for the request was before the notBefore time in the end certificate: Certificate is not valid yet";
		final String wrongTrustAnchorStr = "A certification path could not be constructed for the specified trust anchor(s), but a path exists for one of the trust anchors specified in the server's default validation policy;";
		final String noValidCertPathStr = "The server could not construct a sequence of intermediate certificates between the trust anchor and the target certificate that satisfied the request";
		final String revokedStr = "Certificate has been revoked";
		final String invalidKeyPurposeStr = "The extended key usage extension in the end certificate does not satisfy the validation policy";
		final String invalidKeyUsageStr = "The keyUsage extension in the end certificate does not satisfy the validation policy";
		final String invalidCertPolicyStr = "The path is not valid under any of the policies defined in the validation policy";
		final String weakCertKeyStr = "The key size of the certificate does not meet the requirement of the validation policy";
		final String weakCertHashStr = "The hashing algorithm of the certificate does not meet the requirement of the validation policy";

		switch (string) {
		case expired: {
			return expiredStr;
		}
		case notYetValid: {
			return notYetValidStr;
		}
		case wrongTrustAnchor: {
			return wrongTrustAnchorStr;
		}
		case noValidCertPath: {
			return noValidCertPathStr;
		}
		case revoked: {
			return revokedStr;
		}
		case invalidKeyPurpose: {
			return invalidKeyPurposeStr;
		}
		case invalidKeyUsage: {
			return invalidKeyUsageStr;
		}
		case invalidCertPolicy: {
			return invalidCertPolicyStr;
		}
		case weakCertKey: {
			return weakCertKeyStr;
		}
		case weakCertHash: {
			return weakCertHashStr;
		}
		default: {
			return "Unknown validation error: " + string;
		}
		}
	}

	public static String certPathNotValidStatus(ASN1Integer asn1Integer) {
		/*
		 * ReplyStatus status values for: id-stc-build-status-checked-pkc-path
		 * 
		 * https://tools.ietf.org/html/rfc5055#section-4.9.4
		 * 
		 * This client ONLY performs this status check, IF other status checks are
		 * supported in the future, then logic for the other status checks SHOULD be
		 * added.
		 */
		// private final static int IntIdStcThreeStatusZero = 0;
		final int IntIdStcThreeStatusOne = 1;
		final int IntIdStcThreeStatusTwo = 2;
		final int IntIdStcThreeStatusThree = 3;
		final int IntIdStcThreeStatusFour = 4;
		// private final static String idStcThreeStatusZero = "Certificate path
		// valid";
		final String idStcThreeStatusOne = "No valid path";
		final String idStcThreeStatusTwo = "Revocation off-line";
		final String idStcThreeStatusThree = "Revocation unavailable";
		final String idStcThreeStatusFour = "No known source for revocation information";

		switch (asn1Integer.getValue().intValue()) {
		case IntIdStcThreeStatusOne: {
			return idStcThreeStatusOne;
		}
		case IntIdStcThreeStatusTwo: {
			return idStcThreeStatusTwo;
		}
		case IntIdStcThreeStatusThree: {
			return idStcThreeStatusThree;
		}
		case IntIdStcThreeStatusFour: {
			return idStcThreeStatusFour;
		}
		default: {
			return "Unknown path construction error: " + asn1Integer.getValue().intValue();
		}
		}

	}

	private VSSResponse serviceFailure(String transactionResultToken, String transactionResultText,
			VSSResponse result) {
		TransactionResult tResult = new TransactionResult();
		tResult.transactionResultToken = transactionResultToken;
		tResult.transactionResultText = transactionResultText;
		result.transactionResult = tResult;
		return result;
	}

	private VSSResponse failure(String invalidityReasonText, boolean isAffirmativelyInvalid, VSSResponse result, ResultByCertificateData certResult) {
		TransactionResult tResult = new TransactionResult();
		tResult.transactionResultToken = "SUCCESS";
		tResult.transactionResultText = "Validation Operation Completed Successfully";
		result.transactionResult = tResult;
		//ResultByCertificateData certResult = result.validationResult.resultsByCertificateList
		//		.get(0).resultByCertificate;
		certResult.validationResultToken = "FAIL";
		ValidationFailureData validationFailureData = new ValidationFailureData();
		validationFailureData.isAffirmativelyInvalid = isAffirmativelyInvalid;
		InvalidityReason invalidityReason = new InvalidityReason();
		invalidityReason.invalidityReasonToken = "FAIL";
		invalidityReason.invalidityReasonText = invalidityReasonText;
		List<InvalidityReason> invalidityReasonList = new ArrayList<InvalidityReason>();
		invalidityReasonList.add(invalidityReason);
		validationFailureData.invalidityReasonList = invalidityReasonList;
		certResult.validationFailureData = validationFailureData;

		ResultByCertificate resultByCertificate = new ResultByCertificate();
		resultByCertificate.resultByCertificate = certResult;
		if(null == result.validationResult) {
			result.validationResult = new ValidationResult();
		}
		result.validationResult.resultsByCertificateList.add(resultByCertificate);
		return result;
	}

	/**
	 * @return the jceProvider
	 */
	public Provider getJceProvider() {
		return jceProvider;
	}

	/**
	 * @param jceProvider the jceProvider to set
	 */
	public void setJceProvider(Provider jceProvider) {
		this.jceProvider = jceProvider;
	}

}
