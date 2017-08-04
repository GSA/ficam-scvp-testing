package gov.treas.pki.vss.scvp.asn1;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 *    ResponseFlags ::= SEQUENCE {
     fullRequestInResponse      [0] BOOLEAN DEFAULT FALSE,
     responseValidationPolByRef [1] BOOLEAN DEFAULT TRUE,
     protectResponse            [2] BOOLEAN DEFAULT TRUE,
     cachedResponse             [3] BOOLEAN DEFAULT TRUE }


 */
public class ResponseFlags extends ASN1Object {

	private ASN1Boolean fullRequestInResponse = null;
	private ASN1Boolean responseValidationPolByRef = null;
	private ASN1Boolean protectResponse = null;
	private ASN1Boolean cachedResponse = null;
	
	public ResponseFlags(boolean fullRequestInResponse, boolean responseValidationPolByRef, boolean protectResponse, boolean cachedResponse) {
		this.fullRequestInResponse = ASN1Boolean.getInstance(fullRequestInResponse);
		this.responseValidationPolByRef = ASN1Boolean.getInstance(responseValidationPolByRef);
		this.protectResponse = ASN1Boolean.getInstance(protectResponse);
		this.cachedResponse = ASN1Boolean.getInstance(cachedResponse);
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || fullRequestInResponse.isTrue()) {
			v.add(new DERTaggedObject(false, 0, fullRequestInResponse));
		}
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || !responseValidationPolByRef.isTrue()) {
			v.add(new DERTaggedObject(false, 1, responseValidationPolByRef));
		}
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || !protectResponse.isTrue()) {
			v.add(new DERTaggedObject(false, 2, protectResponse));
		}
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || !cachedResponse.isTrue()) {
			v.add(new DERTaggedObject(false, 3, cachedResponse));
		}
		return new DERSequence(v);
	}

	public ASN1Boolean getFullRequestInResponse(){
		return this.fullRequestInResponse;
	}
	public ASN1Boolean getResponseValidationPolByRef(){
		return this.responseValidationPolByRef;
	}
	public ASN1Boolean getProtectResponse(){
		return this.protectResponse;
	}
	public ASN1Boolean getCachedResponse(){
		return this.cachedResponse;
	}
}
