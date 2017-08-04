package gov.treas.pki.vss.scvp.asn1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/*
 *    ValPolResponse ::= SEQUENCE {
 *      vpResponseVersion               INTEGER,
 *      maxCVRequestVersion             INTEGER,
 *      maxVPRequestVersion             INTEGER,
 *      serverConfigurationID           INTEGER,
 *      thisUpdate                      GeneralizedTime,
 *      nextUpdate                      GeneralizedTime OPTIONAL,
 *      supportedChecks                 CertChecks,
 *      supportedWantBacks              WantBack,
 *      validationPolicies              SEQUENCE OF OBJECT IDENTIFIER,
 *      validationAlgs                  SEQUENCE OF OBJECT IDENTIFIER,
 *      authPolicies                    SEQUENCE OF AuthPolicy,
 *      responseTypes                   ResponseTypes,
 *      defaultPolicyValues             RespValidationPolicy,
 *      revocationInfoTypes             RevocationInfoTypes,
 *      signatureGeneration             SEQUENCE OF AlgorithmIdentifier,
 *      signatureVerification           SEQUENCE OF AlgorithmIdentifier,
 *      hashAlgorithms                  SEQUENCE SIZE (1..MAX) OF
 *                                         OBJECT IDENTIFIER,
 *      serverPublicKeys                SEQUENCE OF KeyAgreePublicKey
 *                                         OPTIONAL,
 *      clockSkew                       INTEGER DEFAULT 10,
 *      requestNonce                    OCTET STRING OPTIONAL }
 *  
 */
public class ValPolResponse extends ASN1Object {

	private ASN1Integer vpResponseVersion = null;
	private ASN1Integer maxCVRequestVersion = null;
	private ASN1Integer maxVPRequestVersion = null;
	private ASN1Integer serverConfigurationID = null;
	private ASN1GeneralizedTime thisUpdate = null;
	private ASN1GeneralizedTime nextUpdate = null;
	private CertChecks supportedChecks = null;
	private WantBack supportedWantBacks = null;
	private ASN1Sequence validationPolicies = null;
	private ASN1Sequence validationAlgs = null;
	private ASN1Sequence authPolicies = null;
	private ResponseTypes responseTypes = null;
	private ValidationPolicy defaultPolicyValues = null;
	private RevocationInfoTypes revocationInfoTypes = null;
	private ASN1Sequence signatureGeneration = null;
	private ASN1Sequence signatureVerification = null;
	private ASN1Sequence hashAlgorithms = null;
	private ASN1Sequence serverPublicKeys = null;
	private ASN1Integer clockSkew = null;
	private ASN1OctetString requestNonce = null;
	
	public static final ASN1ObjectIdentifier idCtScvpvalPolResponse = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.13").intern();

	public static ValPolResponse getInstance(Object obj) {
		if (obj == null || obj instanceof ValPolResponse) {
			return (ValPolResponse)obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ValPolResponse((ASN1Sequence)obj);
		} else if (obj instanceof byte[]) {
			try {
				return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
			} catch (IOException e) {
				throw new IllegalArgumentException("unable to parse encoded object");
			}
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	private ValPolResponse(ASN1Sequence seq) {
		Iterator<ASN1Encodable> it = seq.iterator();
		/*
		 * Get the mandatory objects
		 */
		this.vpResponseVersion = ASN1Integer.getInstance(it.next());
		this.maxCVRequestVersion = ASN1Integer.getInstance(it.next());
		this.maxVPRequestVersion = ASN1Integer.getInstance(it.next());
		this.serverConfigurationID = ASN1Integer.getInstance(it.next());
		this.thisUpdate = ASN1GeneralizedTime.getInstance(it.next());
		this.nextUpdate = ASN1GeneralizedTime.getInstance(it.next());
		this.supportedChecks = CertChecks.getInstance(it.next());
		this.supportedWantBacks = WantBack.getInstance(it.next());
		this.validationPolicies = ASN1Sequence.getInstance(it.next());
		this.validationAlgs = ASN1Sequence.getInstance(it.next());
		this.authPolicies = ASN1Sequence.getInstance(it.next());
		this.responseTypes = ResponseTypes.getInstance(it.next());
		this.defaultPolicyValues = ValidationPolicy.getInstance(it.next());
		this.revocationInfoTypes = RevocationInfoTypes.getInstance(it.next());
		this.signatureGeneration = ASN1Sequence.getInstance(it.next());
		this.signatureVerification = ASN1Sequence.getInstance(it.next());
		this.hashAlgorithms = ASN1Sequence.getInstance(it.next());
		/*
		 * Process remaining
		 */
		while (it.hasNext()) {
			ASN1Encodable obj = it.next();
			if (obj instanceof ASN1Sequence) {
				this.serverPublicKeys = (ASN1Sequence) obj;
			} else if (obj instanceof ASN1Integer) {
				this.clockSkew = (ASN1Integer) obj;
			} else if (obj instanceof ASN1OctetString) {
				this.requestNonce = (ASN1OctetString) obj;
			} else
				throw new IllegalArgumentException("unknown object in CertReply: " + obj.getClass().getName());
		}
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		//v.add(...);
		//XXX*** need to sniff out default clockSkew values so those can be omitted
		return new DERSequence(v);
	}

	/**
	 * @return the vpResponseVersion
	 */
	public ASN1Integer getVpResponseVersion() {
		return vpResponseVersion;
	}

	/**
	 * @param vpResponseVersion the vpResponseVersion to set
	 */
	public void setVpResponseVersion(ASN1Integer vpResponseVersion) {
		this.vpResponseVersion = vpResponseVersion;
	}

	/**
	 * @return the maxCVRequestVersion
	 */
	public ASN1Integer getMaxCVRequestVersion() {
		return maxCVRequestVersion;
	}

	/**
	 * @param maxCVRequestVersion the maxCVRequestVersion to set
	 */
	public void setMaxCVRequestVersion(ASN1Integer maxCVRequestVersion) {
		this.maxCVRequestVersion = maxCVRequestVersion;
	}

	/**
	 * @return the maxVPRequestVersion
	 */
	public ASN1Integer getMaxVPRequestVersion() {
		return maxVPRequestVersion;
	}

	/**
	 * @param maxVPRequestVersion the maxVPRequestVersion to set
	 */
	public void setMaxVPRequestVersion(ASN1Integer maxVPRequestVersion) {
		this.maxVPRequestVersion = maxVPRequestVersion;
	}

	/**
	 * @return the serverConfigurationID
	 */
	public ASN1Integer getServerConfigurationID() {
		return serverConfigurationID;
	}

	/**
	 * @param serverConfigurationID the serverConfigurationID to set
	 */
	public void setServerConfigurationID(ASN1Integer serverConfigurationID) {
		this.serverConfigurationID = serverConfigurationID;
	}

	/**
	 * @return the thisUpdate
	 */
	public ASN1GeneralizedTime getThisUpdate() {
		return thisUpdate;
	}

	/**
	 * @param thisUpdate the thisUpdate to set
	 */
	public void setThisUpdate(ASN1GeneralizedTime thisUpdate) {
		this.thisUpdate = thisUpdate;
	}

	/**
	 * @return the nextUpdate
	 */
	public ASN1GeneralizedTime getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * @param nextUpdate the nextUpdate to set
	 */
	public void setNextUpdate(ASN1GeneralizedTime nextUpdate) {
		this.nextUpdate = nextUpdate;
	}

	/**
	 * @return the supportedChecks
	 */
	public CertChecks getSupportedChecks() {
		return supportedChecks;
	}

	/**
	 * @param supportedChecks the supportedChecks to set
	 */
	public void setSupportedChecks(CertChecks supportedChecks) {
		this.supportedChecks = supportedChecks;
	}

	/**
	 * @return the supportedWantBacks
	 */
	public WantBack getSupportedWantBacks() {
		return supportedWantBacks;
	}

	/**
	 * @param supportedWantBacks the supportedWantBacks to set
	 */
	public void setSupportedWantBacks(WantBack supportedWantBacks) {
		this.supportedWantBacks = supportedWantBacks;
	}

	/**
	 * @return the validationPolicies
	 */
	public ASN1ObjectIdentifier[] getValidationPolicies() {
		if (null != validationPolicies) {
			ASN1Encodable[] elements = validationPolicies.toArray();
			ArrayList<ASN1ObjectIdentifier> toReturn = new ArrayList<ASN1ObjectIdentifier>();
			for (ASN1Encodable element: elements) {
				toReturn.add(ASN1ObjectIdentifier.getInstance(element));
			}
			return toReturn.toArray(new ASN1ObjectIdentifier[toReturn.size()]);
		} else {
			return null;
		}
	}

	/**
	 * @param validationPolicies the validationPolicies to set
	 */
	public void setValidationPolicies(ASN1Sequence validationPolicies) {
		this.validationPolicies = validationPolicies;
	}

	/**
	 * @return the validationAlgs
	 */
	public ASN1ObjectIdentifier[] getValidationAlgs() {
		if (null != validationAlgs) {
			ASN1Encodable[] elements = validationAlgs.toArray();
			ArrayList<ASN1ObjectIdentifier> toReturn = new ArrayList<ASN1ObjectIdentifier>();
			for (ASN1Encodable element: elements) {
				toReturn.add(ASN1ObjectIdentifier.getInstance(element));
			}
			return toReturn.toArray(new ASN1ObjectIdentifier[toReturn.size()]);
		} else {
			return null;
		}
	}

	/**
	 * @param validationAlgs the validationAlgs to set
	 */
	public void setValidationAlgs(ASN1Sequence validationAlgs) {
		this.validationAlgs = validationAlgs;
	}

	/**
	 * @return the authPolicies
	 */
	public ASN1Sequence getAuthPolicies() {
		return authPolicies;
	}

	/**
	 * @param authPolicies the authPolicies to set
	 */
	public void setAuthPolicies(ASN1Sequence authPolicies) {
		this.authPolicies = authPolicies;
	}

	/**
	 * @return the responseTypes
	 */
	public ResponseTypes getResponseTypes() {
		return responseTypes;
	}

	/**
	 * @param responseTypes the responseTypes to set
	 */
	public void setResponseTypes(ResponseTypes responseTypes) {
		this.responseTypes = responseTypes;
	}

	/**
	 * @return the defaultPolicyValues
	 */
	public ValidationPolicy getDefaultPolicyValues() {
		return defaultPolicyValues;
	}

	/**
	 * @param defaultPolicyValues the defaultPolicyValues to set
	 */
	public void setDefaultPolicyValues(ValidationPolicy defaultPolicyValues) {
		this.defaultPolicyValues = defaultPolicyValues;
	}

	/**
	 * @return the revocationInfoTypes
	 */
	public RevocationInfoTypes getRevocationInfoTypes() {
		return revocationInfoTypes;
	}

	/**
	 * @param revocationInfoTypes the revocationInfoTypes to set
	 */
	public void setRevocationInfoTypes(RevocationInfoTypes revocationInfoTypes) {
		this.revocationInfoTypes = revocationInfoTypes;
	}

	/**
	 * @return the signatureGeneration
	 */
	public ASN1Sequence getSignatureGeneration() {
		return signatureGeneration;
	}

	/**
	 * @param signatureGeneration the signatureGeneration to set
	 */
	public void setSignatureGeneration(ASN1Sequence signatureGeneration) {
		this.signatureGeneration = signatureGeneration;
	}

	/**
	 * @return the signatureVerification
	 */
	public ASN1Sequence getSignatureVerification() {
		return signatureVerification;
	}

	/**
	 * @param signatureVerification the signatureVerification to set
	 */
	public void setSignatureVerification(ASN1Sequence signatureVerification) {
		this.signatureVerification = signatureVerification;
	}

	/**
	 * @return the hashAlgorithms
	 */
	public ASN1Sequence getHashAlgorithms() {
		return hashAlgorithms;
	}

	/**
	 * @param hashAlgorithms the hashAlgorithms to set
	 */
	public void setHashAlgorithms(ASN1Sequence hashAlgorithms) {
		this.hashAlgorithms = hashAlgorithms;
	}

	/**
	 * @return the serverPublicKeys
	 */
	public ASN1Sequence getServerPublicKeys() {
		return serverPublicKeys;
	}

	/**
	 * @param serverPublicKeys the serverPublicKeys to set
	 */
	public void setServerPublicKeys(ASN1Sequence serverPublicKeys) {
		this.serverPublicKeys = serverPublicKeys;
	}

	/**
	 * @return the clockSkew
	 */
	public ASN1Integer getClockSkew() {
		return clockSkew;
	}

	/**
	 * @param clockSkew the clockSkew to set
	 */
	public void setClockSkew(ASN1Integer clockSkew) {
		this.clockSkew = clockSkew;
	}

	/**
	 * @return the requestNonce
	 */
	public ASN1OctetString getRequestNonce() {
		return requestNonce;
	}

	/**
	 * @param requestNonce the requestNonce to set
	 */
	public void setRequestNonce(ASN1OctetString requestNonce) {
		this.requestNonce = requestNonce;
	}

}
