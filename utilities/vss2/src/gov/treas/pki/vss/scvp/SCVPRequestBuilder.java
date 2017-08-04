package gov.treas.pki.vss.scvp;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;

import gov.treas.pki.vss.scvp.asn1.CVRequest;
import gov.treas.pki.vss.scvp.asn1.CertChecks;
import gov.treas.pki.vss.scvp.asn1.CertReferences;
import gov.treas.pki.vss.scvp.asn1.PKCReference;
import gov.treas.pki.vss.scvp.asn1.Query;
import gov.treas.pki.vss.scvp.asn1.ResponseFlags;
import gov.treas.pki.vss.scvp.asn1.SCVPRequest;
import gov.treas.pki.vss.scvp.asn1.ValidationAlg;
import gov.treas.pki.vss.scvp.asn1.ValidationPolRef;
import gov.treas.pki.vss.scvp.asn1.ValidationPolicy;
import gov.treas.pki.vss.scvp.asn1.WantBack;

public class SCVPRequestBuilder {

	/*
	 * The core of the request
	 */
	private SCVPRequest encapRequest = null;
	private CVRequest request = null;
	private Query query = null;
	private ValidationPolicy validationPolicy = null;
	/*
	 * ValidationPolicy Contents
	 */
	private ValidationAlg validationAlg = null;
	private ValidationPolRef validationPolRef = null;
	private ASN1Sequence initialPolicies = null;
	private ASN1Boolean inhibitAnyPolicy = null;
	private ASN1Boolean requireExplicitPolicy = null;
	private ASN1Boolean inhibitPolicyMapping = null;
	private ASN1Sequence anchors = null;
	/*
	 * Query Contents
	 */
	private CertChecks checks = null;
	private CertReferences queriedCerts = null;
	private WantBack wantBack = null;
	private ResponseFlags responseFlags = null;
	/*
	 * CVRequest Contents
	 */
	private GeneralName requestorName = null;
	private DERUTF8String requestorText = null;
	private ASN1OctetString requestNonce = null;

	public SCVPRequestBuilder() {
		// Create a null instance of our class...
		// Then build (and encapsulate) the request manually using setters
	}

	public void setCertChecks(CertChecks checks) {
		this.checks = checks;
	}

	public void addCertCheck(ASN1ObjectIdentifier check) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (this.checks != null) {
			ASN1Encodable[] oids = checks.toArray();
			for (ASN1Encodable oid : oids) {
				v.add(oid);
			}
			v.add(check);
		} else {
			v.add(check);
		}
		this.checks = CertChecks.getInstance(new DERSequence(v));
	}

	public void setTrustAnchors(ASN1Sequence anchors) {
		this.anchors = anchors;
	}

	public void addTrustAnchor(Certificate cert) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (this.anchors != null) {
			ASN1Encodable[] pkcRefs = anchors.toArray();
			for (ASN1Encodable ref : pkcRefs) {
				v.add(ref);
			}
			v.add(new PKCReference(cert));
		} else {
			v.add(new PKCReference(cert));
		}
		this.anchors = new DERSequence(v);
	}

	public void setValidationPolRef(ASN1ObjectIdentifier valPolId, ASN1Object valPolParams) {
		this.validationPolRef = new ValidationPolRef(valPolId, valPolParams);
	}

	public void setUserPolicySet(ASN1Sequence initialPolicies) {
		this.initialPolicies = initialPolicies;
	}

	public void addUserPolicy(ASN1ObjectIdentifier policy) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (this.initialPolicies != null) {
			ASN1Encodable[] oids = initialPolicies.toArray();
			for (ASN1Encodable oid : oids) {
				v.add(oid);
			}
			v.add(policy);
		} else {
			v.add(policy);
		}
		this.initialPolicies = new DERSequence(v);
	}

	public void setInhibitAnyPolicy(boolean inhibit) {
		this.inhibitAnyPolicy = ASN1Boolean.getInstance(inhibit);
	}

	public void setRequireExplicitPolicy(boolean require) {
		this.requireExplicitPolicy = ASN1Boolean.getInstance(require);
	}

	public void setInhibitPolicyMapping(boolean inhibit) {
		this.inhibitPolicyMapping = ASN1Boolean.getInstance(inhibit);
	}

	public void setCertReference(Certificate cert) {
		this.queriedCerts = new CertReferences(new PKCReference(cert));
	}

	public void addCertReference(Certificate cert) {
		this.queriedCerts = new CertReferences(new PKCReference(cert));
	}
	public void setCertReferences(CertReferences certs) {
		this.queriedCerts = certs;
	}

	public void setRequestorName(String reqName) {
		this.requestorName = new GeneralName(6, reqName);
	}

	public void setRequestorText(String reqText) {
		this.requestorText = new DERUTF8String(reqText);
	}

	public void generateNonce(int nonceSize) {
		SecureRandom random = null;
		byte[] nonce = null;
		nonce = new byte[nonceSize];
		random = new SecureRandom();
		random.nextBytes(nonce);
		this.requestNonce = new DEROctetString(nonce);
	}

	public SCVPRequest buildRequest() {
		/*
		 * Start by building the ValidationPolicy per the setters called.
		 */
		validationPolicy = new ValidationPolicy(validationPolRef, null, initialPolicies, inhibitPolicyMapping,
				requireExplicitPolicy, inhibitAnyPolicy, anchors, null, null, null);
		/*
		 * Next, we build the Query with the settings called, adding the
		 * ValidationPolicy.
		 */
		query = new Query(queriedCerts, checks, wantBack, validationPolicy, responseFlags, null, null, null, null, null,
				null);
		/*
		 * Specify 1.2.840.113549.1.1.11 - sha256WithRSAEncryption for response
		 * signing
		 */
		// AlgorithmIdentifier sha256WithRSAEncryption = new
		// AlgorithmIdentifier(new
		// ASN1ObjectIdentifier("1.2.840.113549.1.1.11"));
		/*
		 * Now we construct the CVRequest, and add the Query.
		 */
		request = new CVRequest(query, null, requestNonce, requestorName, null, null, null, null, requestorText);
		/*
		 * Finally, we envelope the CVRequest in a CMS message and return to the
		 * caller.
		 */
		encapRequest = new SCVPRequest(request);
		return encapRequest;
	}

	public SCVPRequest getEncapRequest() {
		return encapRequest;
	}

	public CVRequest getRequest() {
		return request;
	}

	public Query getQuery() {
		return query;
	}

	public ValidationPolicy getValidationPolicy() {
		return validationPolicy;
	}

	/**
	 * @return the wantBack
	 */
	public WantBack getWantBack() {
		return wantBack;
	}

	/**
	 * @param wantBack
	 *            the wantBack to set
	 */
	public void setWantBack(WantBack wantBack) {
		this.wantBack = wantBack;
	}

	public void setResponseFlags(ResponseFlags responseFlags) {
		this.responseFlags = responseFlags;
	}

	/**
	 * @return the validationAlg
	 */
	public ValidationAlg getValidationAlg() {
		return validationAlg;
	}

	/**
	 * @param validationAlg the validationAlg to set
	 */
	public void setValidationAlg(ValidationAlg validationAlg) {
		this.validationAlg = validationAlg;
	}

}
