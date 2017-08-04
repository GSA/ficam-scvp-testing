package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class ValidationPolRef extends ASN1Object {

	public static ValidationPolRef getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static ValidationPolRef getInstance(Object obj) {
		if (obj == null || obj instanceof ValidationPolRef) {
			return (ValidationPolRef)obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ValidationPolRef((ASN1Sequence)obj);
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	private ASN1ObjectIdentifier valPolId = null;
	private ASN1Encodable valPolParams = null;

	public ValidationPolRef(ASN1ObjectIdentifier valPolId, ASN1Encodable valPolParams) {
		this.valPolId = valPolId;
		this.valPolParams = valPolParams;
	}

	private ValidationPolRef(ASN1Sequence seq) {
		if (seq.size() < 1 || seq.size() > 2) {
			throw new IllegalArgumentException("Bad sequence size: " + seq.size());
		}
		this.valPolId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
		if (seq.size() == 2) {
			this.valPolParams = seq.getObjectAt(1);
		} else {
			this.valPolParams = null;
		}
	}

	/*
	 *       ValidationPolRef::= SEQUENCE {
	        valPolId              OBJECT IDENTIFIER,
	        valPolParams          ANY DEFINED BY valPolId OPTIONAL }

	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(valPolId);
		if (valPolParams != null) {
			v.add(valPolParams);
		}
		return new DERSequence(v);
	}

}
