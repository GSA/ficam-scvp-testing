package gov.treas.pki.vss.scvp.asn1;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * @author tejohnson
 * 
 *         https://tools.ietf.org/html/rfc5055#section-3
 * 
 */

/*<pre>
 *      CVRequest ::= SEQUENCE {
        cvRequestVersion        INTEGER DEFAULT 1,
        query                   Query,
        requestorRef        [0] GeneralNames OPTIONAL,
        requestNonce        [1] OCTET STRING OPTIONAL,
        requestorName       [2] GeneralName OPTIONAL,
        responderName       [3] GeneralName OPTIONAL,
        requestExtensions   [4] Extensions OPTIONAL,
        signatureAlg        [5] AlgorithmIdentifier OPTIONAL,
        hashAlg             [6] OBJECT IDENTIFIER OPTIONAL,
        requestorText       [7] UTF8String (SIZE (1..256)) OPTIONAL }
 *</pre> 
 */

public class CVRequest extends ASN1Object {

	private final ASN1Integer cvRequestVersion = new ASN1Integer(1);
	private Query query = null;
	private GeneralNames requestorRef = null;
	private ASN1OctetString requestNonce = null;
	private GeneralName requestorName = null;
	private GeneralName responderName = null;
	private Extensions requestExtensions = null;
	private AlgorithmIdentifier signatureAlg = null;
	private ASN1ObjectIdentifier hashAlg = null;
	private DERUTF8String requestorText = null;

	public CVRequest(Query query, GeneralNames requestorRef,
			ASN1OctetString requestNonce, GeneralName requestorName,
			GeneralName responderName, Extensions requestExtensions,
			AlgorithmIdentifier signatureAlg, ASN1ObjectIdentifier hashAlg,
			DERUTF8String requestorText) {
		this.query = query;
		this.requestorRef = requestorRef;
		this.requestNonce = requestNonce;
		this.requestorName = requestorName;
		this.responderName = responderName;
		this.requestExtensions = requestExtensions;
		this.signatureAlg = signatureAlg;
		this.hashAlg = hashAlg;
		this.requestorText = requestorText;
	}

	private CVRequest(ASN1Sequence seq) {
	}

	public static CVRequest getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static CVRequest getInstance(Object obj) {
		if (obj instanceof CVRequest) {
			return (CVRequest) obj;
		} else if (obj != null) {
			return new CVRequest(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();

		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || !cvRequestVersion.equals(new ASN1Integer(1))) {
			v.add(cvRequestVersion);
		}
		v.add(query);
		if (requestorRef != null) {
			v.add(new DERTaggedObject(false, 0, requestorRef));
		}
		if (requestNonce != null) {
			v.add(new DERTaggedObject(false, 1, requestNonce));
		}
		if (requestorName != null) {
			v.add(new DERTaggedObject(false, 2, requestorName));
		}
		if (responderName != null) {
			v.add(new DERTaggedObject(false, 3, responderName));
		}
		if (requestExtensions != null) {
			v.add(new DERTaggedObject(false, 4, requestExtensions));
		}
		if (signatureAlg != null) {
			v.add(new DERTaggedObject(false, 5, signatureAlg));
		}
		if (hashAlg != null) {
			v.add(new DERTaggedObject(false, 6, hashAlg));
		}
		if (requestorText != null) {
			v.add(new DERTaggedObject(false, 7, requestorText));
		}
		return new DERSequence(v);
	}

	/**
	 * @return the query
	 */
	public Query getQuery() {
		return query;
	}

	/**
	 * @param query the query to set
	 */
	public void setQuery(Query query) {
		this.query = query;
	}

	/**
	 * @return the requestorRef
	 */
	public GeneralNames getRequestorRef() {
		return requestorRef;
	}

	/**
	 * @param requestorRef the requestorRef to set
	 */
	public void setRequestorRef(GeneralNames requestorRef) {
		this.requestorRef = requestorRef;
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

	/**
	 * @return the requestorName
	 */
	public GeneralName getRequestorName() {
		return requestorName;
	}

	/**
	 * @param requestorName the requestorName to set
	 */
	public void setRequestorName(GeneralName requestorName) {
		this.requestorName = requestorName;
	}

	/**
	 * @return the responderName
	 */
	public GeneralName getResponderName() {
		return responderName;
	}

	/**
	 * @param responderName the responderName to set
	 */
	public void setResponderName(GeneralName responderName) {
		this.responderName = responderName;
	}

	/**
	 * @return the requestExtensions
	 */
	public Extensions getRequestExtensions() {
		return requestExtensions;
	}

	/**
	 * @param requestExtensions the requestExtensions to set
	 */
	public void setRequestExtensions(Extensions requestExtensions) {
		this.requestExtensions = requestExtensions;
	}

	/**
	 * @return the signatureAlg
	 */
	public AlgorithmIdentifier getSignatureAlg() {
		return signatureAlg;
	}

	/**
	 * @param signatureAlg the signatureAlg to set
	 */
	public void setSignatureAlg(AlgorithmIdentifier signatureAlg) {
		this.signatureAlg = signatureAlg;
	}

	/**
	 * @return the hashAlg
	 */
	public ASN1ObjectIdentifier getHashAlg() {
		return hashAlg;
	}

	/**
	 * @param hashAlg the hashAlg to set
	 */
	public void setHashAlg(ASN1ObjectIdentifier hashAlg) {
		this.hashAlg = hashAlg;
	}

	/**
	 * @return the requestorText
	 */
	public DERUTF8String getRequestorText() {
		return requestorText;
	}

	/**
	 * @param requestorText the requestorText to set
	 */
	public void setRequestorText(DERUTF8String requestorText) {
		this.requestorText = requestorText;
	}

	/**
	 * @return the cvRequestVersion
	 */
	public ASN1Integer getCvRequestVersion() {
		return cvRequestVersion;
	}

}
