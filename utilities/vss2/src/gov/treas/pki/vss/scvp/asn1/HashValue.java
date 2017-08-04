/**
 * 
 */
package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 */
public class HashValue extends ASN1Object {

	private AlgorithmIdentifier algorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
	private ASN1OctetString value = null;

	public static HashValue getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static HashValue getInstance(Object obj) {
		if (obj == null || obj instanceof HashValue) {
			return (HashValue)obj;
		} else if (obj instanceof DEROctetString) {
			return new HashValue(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26")), (DEROctetString) obj);
		} else if (obj instanceof ASN1Sequence) {
			return new HashValue((ASN1Sequence)obj);
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	/**
	 * 
	 */
	public HashValue(AlgorithmIdentifier algorithm, DEROctetString value) {
		this.algorithm = algorithm;
		this.value = value;
	}
	
	private HashValue(ASN1Sequence seq) {
		this.algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
		this.value = ASN1OctetString.getInstance(seq.getObjectAt(1));
	}

	/* (non-Javadoc)
	 * 
	 *  *   HashValue ::= SEQUENCE {
     algorithm         AlgorithmIdentifier DEFAULT { algorithm sha-1 },
     value             OCTET STRING }
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(algorithm);
		v.add(value);
		return new DERSequence(v); 
	}

	/**
	 * @return the algorithm
	 */
	public AlgorithmIdentifier getAlgorithm() {
		return algorithm;
	}

	/**
	 * @param algorithm the algorithm to set
	 */
	public void setAlgorithm(AlgorithmIdentifier algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * @return the value
	 */
	public ASN1OctetString getValue() {
		return value;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(ASN1OctetString value) {
		this.value = value;
	}

}
