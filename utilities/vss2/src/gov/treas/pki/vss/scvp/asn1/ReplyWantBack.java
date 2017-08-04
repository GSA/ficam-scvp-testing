package gov.treas.pki.vss.scvp.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

public class ReplyWantBack extends ASN1Object {

	private ASN1ObjectIdentifier wb;
	private ASN1OctetString value;

	public ReplyWantBack(ASN1ObjectIdentifier wb, byte[] value) {
		this(wb, new DEROctetString(value));
	}

	public ReplyWantBack(ASN1ObjectIdentifier wb, ASN1OctetString value) {
		this.wb = wb;
		this.value = value;
	}

	private ReplyWantBack(ASN1Sequence seq) {
		if (seq.size() == 2) {
			this.wb = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			this.value = ASN1OctetString.getInstance(seq.getObjectAt(1));
		} else {
			throw new IllegalArgumentException("Bad sequence size: " + seq.size());
		}
	}

	public static ReplyWantBack getInstance(Object obj) {
		if (obj instanceof ReplyWantBack) {
			return (ReplyWantBack)obj;
		} else if (obj != null) {
			return new ReplyWantBack(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	public ASN1ObjectIdentifier getWb() {
		return wb;
	}

	public ASN1OctetString getValue() {
		return value;
	}

	public ASN1Encodable getParsedValue() {
		return convertValueToObject(this);
	}

	public int hashCode() {
		return ~(this.getValue().hashCode() ^ this.getWb().hashCode());
	}
	
	public boolean equals(Object  o) {
		if (!(o instanceof ReplyWantBack)) {
			return false;
		}
		ReplyWantBack other = (ReplyWantBack)o;
		return other.getWb().equals(this.getWb())
				&& other.getValue().equals(this.getValue());
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(wb);
		v.add(value);
		return new DERSequence(v);
	}

	/**
	 * Convert the value of the passed in ReplyWantBack to an object
	 * @param ReplyWantBack the ReplyWantBack to parse
	 * @return the object the value string contains
	 * @exception IllegalArgumentException if conversion is not possible
	 */
	private static ASN1Primitive convertValueToObject(ReplyWantBack replyWantBack) throws IllegalArgumentException {
		try {
			return ASN1Primitive.fromByteArray(replyWantBack.getValue().getOctets());
		} catch (IOException e) {
			throw new IllegalArgumentException("can't convert ReplyWantBack: " +  e);
		}
	}

}
