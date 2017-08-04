package gov.treas.pki.vss.scvp.asn1;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

/*
 *       ValPolRequest ::= SEQUENCE {
        vpRequestVersion           INTEGER DEFAULT 1,
        requestNonce               OCTET STRING }

 */
public class ValPolRequest extends ASN1Object{

	private final ASN1Integer vpRequestVersion = new ASN1Integer(1);
	private ASN1OctetString requestNonce = null;
	
	public ValPolRequest(ASN1OctetString requestNonce) {
		this.requestNonce = requestNonce;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || !vpRequestVersion.equals(new ASN1Integer(1))) {
			v.add(vpRequestVersion);
		}
		if (null != requestNonce) {
			v.add(requestNonce);
		}
		return new DERSequence(v);
	}

}
