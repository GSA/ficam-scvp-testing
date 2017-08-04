package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Certificate;

/*
 *    PKCReference ::= CHOICE {
     cert        [0] Certificate,
     pkcRef      [1] SCVPCertID }

 */
public class PKCReference extends ASN1Object implements ASN1Choice {
	
	private DERTaggedObject ref = null;
	private Certificate cert = null;
	private SCVPCertID scvpCertId = null;

	public PKCReference(Certificate cert) {
		this.ref = new DERTaggedObject(false, 0, cert);
		this.cert = cert;
	}

	public PKCReference(SCVPCertID id) {
		this.ref = new DERTaggedObject(false, 1, id);
		this.scvpCertId = id;
	}

	public PKCReference(ASN1TaggedObject ref) {
		this.ref = (DERTaggedObject) ref;
		switch (this.ref.getTagNo()) {
			case 0:
				this.cert = Certificate.getInstance(this.ref, false);
				break;
			case 1:
				//this.scvpCertId = SCVPCertID.getInstance(this.ref);
				break;
		}
	}

	public PKCReference getInstance(Object  o) {
		if (o == null || o instanceof PKCReference) {
			return (PKCReference)o;
		} else if (o instanceof ASN1TaggedObject) {
			return new PKCReference((ASN1TaggedObject)o);
		}
		throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return new DERTaggedObject(false, 0, ref);
	}

	public Certificate getCert() {
		return cert;
	}

	public SCVPCertID getScvpCertId() {
		return scvpCertId;
	}
}
