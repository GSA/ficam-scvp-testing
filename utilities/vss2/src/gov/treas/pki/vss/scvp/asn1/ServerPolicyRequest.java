package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 * ContentInfo {
        contentType        id-ct-scvp-valPolRequest,
                                      -- (1.2.840.113549.1.9.16.1.12)
        content            ValPolRequest }
 */
public class ServerPolicyRequest extends ASN1Object{

	public static final ASN1ObjectIdentifier idCtScvpValPolRequest = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.12");

	private ASN1ObjectIdentifier contentType = null;
	private ValPolRequest request = null;
	
	public ServerPolicyRequest(ValPolRequest request) {
		this.contentType = idCtScvpValPolRequest;
		this.request = request;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(contentType);
		if (request != null) {
			v.add(new DERTaggedObject(true, 0, request));
		}
		return new DERSequence(v);
	}

}
