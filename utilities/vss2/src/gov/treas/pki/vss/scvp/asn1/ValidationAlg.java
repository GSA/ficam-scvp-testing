package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class ValidationAlg extends ASN1Object {

	public final static ASN1ObjectIdentifier idSvpNameValAlg = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.19.2").intern();
	public final static ASN1ObjectIdentifier idSvpBasicValAlg = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.19.3").intern();
	public final static ASN1ObjectIdentifier idSvpDnValAlg = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.19.4").intern();

	public static ValidationAlg getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static ValidationAlg getInstance(Object obj) {
		if (obj == null || obj instanceof ValidationAlg) {
			return (ValidationAlg)obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ValidationAlg((ASN1Sequence)obj);
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	private ASN1Encodable parameters = null;
	private ASN1ObjectIdentifier valAlgId = null;

	public ValidationAlg(ASN1ObjectIdentifier valAlgId, ASN1Encodable parameters) {
		this.valAlgId = valAlgId;
		this.parameters = parameters;
	}

	private ValidationAlg(ASN1Sequence seq) {
		if (seq.size() < 1 || seq.size() > 2) {
			throw new IllegalArgumentException("Bad sequence size: " + seq.size());
		}
		this.valAlgId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
		if (seq.size() == 2) {
			this.parameters = seq.getObjectAt(1);
		} else {
			this.parameters = null;
		}
	}

	/*
	 * 
	      ValidationAlg ::= SEQUENCE {
	        valAlgId              OBJECT IDENTIFIER,
	        parameters            ANY DEFINED BY valAlgId OPTIONAL }

	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(valAlgId);
		if (parameters != null) {
			v.add(parameters);
		}
		return new DERSequence(v);
	}

}
