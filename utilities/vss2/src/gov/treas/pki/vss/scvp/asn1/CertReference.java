/**
 * 
 */
package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * @author tejohnson
 *
 *
 *   CertReference ::= CHOICE {
 *      pkc                   PKCReference,
 *      ac                    ACReference }
 */
public class CertReference extends ASN1Object implements ASN1Choice {

	private PKCReference pkc;
	private ACReference ac;

	public CertReference(PKCReference pkc) {
		this.pkc = pkc;
	}

	public CertReference(ACReference ac) {
		this.ac = ac;
	}

	public static CertReference getInstance(Object obj) {
		if (obj == null || obj instanceof CertReference) {
			return (CertReference)obj;
		}
		if (obj instanceof DERTaggedObject) {
			DERTaggedObject dto = (DERTaggedObject)obj;
			switch (dto.getTagNo()) {
			case 0: {
				return new CertReference(new PKCReference(dto));
			}
			case 1: {
				return new CertReference(new PKCReference(dto));
			}
			case 2: {
				return new CertReference(new ACReference(dto));
			}
			case 3: {
				return new CertReference(new ACReference(dto));
			}
			default:
				throw new IllegalArgumentException("unknown tag in factory: " + dto.getTagNo());
			}
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
		
	}

	/* (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		if (this.pkc != null) {
			return new DERSequence(pkc);
		} else if (this.ac != null) {
			return new DERSequence(ac);
		}
		return null;
	}

	public PKCReference getPkc() {
		return pkc;
	}
}
