package gov.treas.pki.vss.scvp.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/*
 *    ResponseTypes  ::= ENUMERATED {
 *     cached-only                (0),
 *     non-cached-only            (1),
 *     cached-and-non-cached      (2) }
 *
 */
public class ResponseTypes extends ASN1Object {
	
	public static final int CACHEDONLY = 0;
	public static final int NONCACHEDONLY = 1;
	public static final int CACHEDANDNONCACHED = 2;

	private ASN1Enumerated value;
	

	public ResponseTypes(int value) {
		this(new ASN1Enumerated(value));
	}

	private ResponseTypes(ASN1Enumerated value) {
		this.value = value;
	}

	public static ResponseTypes getInstance(Object obj) {
		if (obj instanceof ResponseTypes) {
			return (ResponseTypes) obj;
		} else if (obj != null) {
			return new ResponseTypes(ASN1Enumerated.getInstance(obj));
		}
		return null;
	}

	public BigInteger getValue() {
		return value.getValue();
	}

	public ASN1Primitive toASN1Primitive() {
		return value;
	}
}