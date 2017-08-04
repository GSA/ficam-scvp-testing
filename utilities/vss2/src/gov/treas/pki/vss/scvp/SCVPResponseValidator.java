package gov.treas.pki.vss.scvp;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import gov.treas.pki.vss.scvp.asn1.*;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

import gov.treas.pki.vss.crypto.DigestEngine;

import static java.lang.Boolean.TRUE;

public class SCVPResponseValidator {

	/*
	 * Using 10 minute default from RFC 5055,
	 * defined here in milliseconds
	 */
	public static final int MAX_CLOCK_SKEW = 600000;

	private SCVPResponseValidator() {
		/*
		 * This is a class with static methods that will
		 * be used to validate SCVP responses.  For now,
		 * the constructor is hidden.  In the event there
		 * would be a performance benefit to this class being
		 * a singleton, this will change.
		 */
	}

	public static void verifyResponse(CMSSignedData cms, PublicKey issuerSigner, CVRequest cvRequest, CVResponse cvResponse) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, CMSException, SCVPVersionException, SCVPRequestReferenceException, SCVPClockSkewException, SCVPNonceException {
		verifySignature(cms, issuerSigner);
		verifyResponse(cvRequest, cvResponse);
	}

	public static void verifyResponse(CVRequest cvRequest, CVResponse cvResponse) throws SCVPVersionException, SCVPRequestReferenceException, SCVPClockSkewException, SCVPNonceException {
		verifyVersion(cvRequest, cvResponse);
		verifyRequestRef(cvRequest, cvResponse);
		verifyClockSkew(cvRequest, cvResponse);
		verifyNonce(cvRequest, cvResponse);
	}
	
	@SuppressWarnings("unchecked")
	public static void verifySignature(CMSSignedData cms, PublicKey issuerSigner) throws CMSException, CertificateException,
			InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		X509Certificate signerCert = null;
		Store<X509CertificateHolder> store = cms.getCertificates();
		SignerInformationStore signers = cms.getSignerInfos();
		Collection<SignerInformation> c = signers.getSigners();
		Iterator<SignerInformation> it = c.iterator();
		if (it.hasNext()) {
			SignerInformation signer = it.next();
			Collection<X509CertificateHolder> certCollection = store.getMatches(signer.getSID());
			Iterator<X509CertificateHolder> certIt = certCollection.iterator();
			X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
			signerCert = new JcaX509CertificateConverter().getCertificate(cert);
			try {
				signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert));
			} catch (OperatorCreationException e) {
				throw new SignatureException(e);
			}
		}
		/*
		 * Verification of a certificate signature will throw a
		 * SignatureException if the signature is invalid.
		 * 
		 * If we get past this method call are are able to continue, then the we
		 * have verified that the signer was used to sign the SCVP signing
		 * certificate.
		 */
		if (null == signerCert) {
			throw new CMSException("Signer certificate omitted from CMS message.");
		}
		signerCert.verify(issuerSigner);
	}

	public static void verifyVersion(CVRequest cvRequest, CVResponse cvResponse) throws SCVPVersionException {
		int reqVersion = cvRequest.getCvRequestVersion().getValue().intValue();
		int resVersion = cvResponse.getResponseVersion().getValue().intValue();
		if (reqVersion != resVersion) {
			throw new SCVPVersionException("Version between request and response do not match");
		}
	}

	public static void verifyRequestRef(CVRequest cvRequest, CVResponse cvResponse) throws SCVPRequestReferenceException {
		RequestReference requestRef = cvResponse.getRequestRef();
		if(null == requestRef)
		{
			Query q = cvRequest.getQuery();
			if(null != q)
			{
				ResponseFlags rf = q.getResponseFlags();
				if(null != rf)
				{
					if(ASN1Boolean.TRUE == rf.getFullRequestInResponse())
					{
						//It is arguably wrong to throw here. Section 3.2.5.1 of RFC 5055 does not require servers
						//to support returning full requests in responses. However, it does not describe any behavior
						//when the client requests a full request but that is not supported. There is a CVStatusCode
						//defined named fullRequestInResponseUnsupported, but use of the value is not described at all.
						throw new SCVPRequestReferenceException("The full request is not present in the response despite a request for such in the request");
					}
				}
			}
			//the optional requestRef field is absent
			return;
		}
		else if (requestRef.isfullRequest()) {
			if (!cvRequest.equals(requestRef.getFullRequest())) {
				throw new SCVPRequestReferenceException("The full request in the response does not match the original request");
			}
		} else if (requestRef.isRequestHash()) {
			HashValue inResponse = requestRef.getRequestHash();
			byte[] respReqDigest = inResponse.getValue().getOctets();
			byte[] reqDigest;
			try {
				reqDigest = DigestEngine.sHA1Sum(cvRequest.toASN1Primitive().getEncoded());
			} catch (IOException e) {
				throw new SCVPRequestReferenceException("Unable to parse the original request");
			}
			if (!Arrays.areEqual(respReqDigest, reqDigest)) {
				throw new SCVPRequestReferenceException("The digest in the response does not match the digest of the original request");
			}
		}
	}
	
	public static void verifyClockSkew(CVRequest cvRequest, CVResponse cvResponse) throws SCVPClockSkewException {
		Date validationTime = null;
		try {
			validationTime = cvResponse.getProducedAt().getDate();
		} catch (ParseException e) {
			throw new SCVPClockSkewException("Unable to parse ProducedAt from CVResponse", e);
		}
		long now = System.currentTimeMillis();
		Date nowPlusSkew = new Date(now + MAX_CLOCK_SKEW);
		Date nowMinusSkew = new Date(now - MAX_CLOCK_SKEW);
		if (nowPlusSkew.before(validationTime) || nowMinusSkew.after(validationTime)) {
			throw new SCVPClockSkewException("Clock skew exceeds " + MAX_CLOCK_SKEW + " milliseconds");
		}
	}

	public static void verifyNonce(CVRequest cvRequest, CVResponse cvResponse) throws SCVPNonceException {
		if (cvRequest.getRequestNonce() != cvResponse.getRespNonce()) {
			throw new SCVPNonceException("Nonce between request and response do not match");
		}
	}
}
