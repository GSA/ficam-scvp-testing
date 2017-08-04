package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 *    CertReferences ::= CHOICE {
 *      pkcRefs     [0] SEQUENCE SIZE (1..MAX) OF PKCReference,
 *      acRefs      [1] SEQUENCE SIZE (1..MAX) OF ACReference }
 *
 */

public class CertReferences extends ASN1Object implements ASN1Choice {
	
	public static final int pkcRefs = 0;
	public static final int acRefs = 1;
	private ASN1Encodable refs = null;
	
	public CertReferences(PKCReference[] refs) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (PKCReference ref: refs) {
			v.add(ref);
		}
		this.refs = new DERTaggedObject(false, pkcRefs, new DERSequence(v));
	}

	public CertReferences(PKCReference ref) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(ref);
		this.refs = new DERTaggedObject(false, pkcRefs, new DERSequence(v));
	}

	public CertReferences(ACReference[] refs) {
		ASN1EncodableVector v = new ASN1EncodableVector();
		for (ACReference ref: refs) {
			v.add(ref);
		}
		this.refs = new DERTaggedObject(false, acRefs, new DERSequence(v));
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return refs.toASN1Primitive();
	}

}
