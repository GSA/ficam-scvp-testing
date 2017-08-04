package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

public class RequestReference extends ASN1Object implements ASN1Choice {

	private DERTaggedObject ref = null;

	public RequestReference(HashValue requestHash) {
		this.ref = new DERTaggedObject(false, 0, requestHash);
	}

	public RequestReference(CVRequest fullRequest) {
		this.ref = new DERTaggedObject(false, 1, fullRequest);
	}
	
	public RequestReference(ASN1TaggedObject ref) {
		this.ref = (DERTaggedObject) ref;
	}

	public static RequestReference getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(DERTaggedObject.getInstance(obj, explicit));
	}

	public static RequestReference getInstance(Object  o) {
		if (o == null || o instanceof RequestReference) {
			return (RequestReference)o;
		} else if (o instanceof ASN1TaggedObject) {
			return new RequestReference((ASN1TaggedObject)o);
		}
		throw new IllegalArgumentException("unknown object in factory: " + o.getClass().getName());
	}

	public boolean isRequestHash() {
		return ref.getTagNo() == 0;
	}

	public boolean isfullRequest() {
		return ref.getTagNo() == 1;
	}

	public HashValue getRequestHash() {
		return HashValue.getInstance(ref.getObject());
	}

	public CVRequest getFullRequest() {
		return CVRequest.getInstance(ref.getObject());
	}

	/*
	 *       RequestReference ::= CHOICE {
	        requestHash       [0] HashValue, -- hash of CVRequest
	        fullRequest       [1] CVRequest }

	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		return ref.toASN1Primitive();
	}

}
