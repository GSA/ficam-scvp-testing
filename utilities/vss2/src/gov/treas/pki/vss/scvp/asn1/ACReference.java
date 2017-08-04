package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AttributeCertificate;

/*
 *    ACReference ::= CHOICE {
     attrCert    [2] AttributeCertificate,
     acRef       [3] SCVPCertID }

 */
public class ACReference extends ASN1Object implements ASN1Choice {

	private ASN1TaggedObject ref = null;

	public ACReference(ASN1TaggedObject ref) {
		this.ref = ref;
	}

	public ACReference(AttributeCertificate attrCert) {
		this.ref = new DERTaggedObject(false, 2, attrCert);
	}

	public ACReference(SCVPCertID acRef) {
		this.ref = new DERTaggedObject(false, 3, acRef);
	}

	public ACReference getInstance(Object  o) {
		if (o == null || o instanceof PKCReference) {
			return (ACReference)o;
		} else if (o instanceof ASN1TaggedObject) {
			return new ACReference((ASN1TaggedObject)o);
		}
		throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return ref.toASN1Primitive();
	}

}
