package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

/*
 *       OtherRevInfo ::= SEQUENCE {
        riType                     OBJECT IDENTIFIER,
        riValue                    ANY DEFINED BY riType }

 */
public class OtherRevInfo extends ASN1Object {

	private ASN1ObjectIdentifier riType = null;
	private ASN1Object riValue = null;
	
	public OtherRevInfo() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(riType);
		v.add(riValue);
		return new DERSequence(v);
	}

}
