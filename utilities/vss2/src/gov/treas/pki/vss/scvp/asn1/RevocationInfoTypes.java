package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;

/*
 *      RevocationInfoTypes ::= BIT STRING {
 *        fullCRLs                   (0),
 *        deltaCRLs                  (1),
 *        indirectCRLs               (2),
 *        oCSPResponses              (3) }
 *
 */
public class RevocationInfoTypes extends ASN1Object {
	
	public static final int FULLCRLS = 0;
	public static final int DELTACRLS = 1;
	public static final int INDIRECTCRLS = 2;
	public static final int OCSPRESPONSES = 3;

	private DERBitString value;
	

	public RevocationInfoTypes(int value) {
		this(new DERBitString(value));
	}

	private RevocationInfoTypes(DERBitString value) {
		this.value = value;
	}

	public static RevocationInfoTypes getInstance(Object obj) {
		if (obj instanceof RevocationInfoTypes) {
			return (RevocationInfoTypes) obj;
		} else if (obj != null) {
			return new RevocationInfoTypes(DERBitString.getInstance(obj));
		}
		return null;
	}

	public int getValue() {
		return value.intValue();
	}

	public ASN1Primitive toASN1Primitive() {
		return value;
	}
}