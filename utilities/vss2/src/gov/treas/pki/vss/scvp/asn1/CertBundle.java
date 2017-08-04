package gov.treas.pki.vss.scvp.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Certificate;

public class CertBundle extends ASN1Object {

	/**
	 * Field value.
	 */
	private ASN1Sequence value;

	public CertBundle(Enumeration<Certificate> certBundle) {
		final ASN1EncodableVector v = new ASN1EncodableVector();
		while (certBundle.hasMoreElements()) {
			v.add(certBundle.nextElement());
		}
		this.value = new DERSequence(v);
	}
	
	private CertBundle(ASN1Sequence value) {
		this.value = value;
	}

	public static CertBundle getInstance(Object obj) {
		if (obj instanceof CertBundle) {
			return (CertBundle) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new CertBundle(ASN1Sequence.getInstance(obj));
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	public Enumeration<?> getValues() {
		return this.value.getObjects();
	}

	/**
	 * Method toASN1Primitive.
	 * @return ASN1Primitive
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		return this.value;
	}

}
