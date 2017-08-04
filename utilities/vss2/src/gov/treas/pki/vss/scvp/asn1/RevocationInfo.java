package gov.treas.pki.vss.scvp.asn1;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.CertificateList;

/*
 *       RevocationInfo ::= CHOICE {
        crl                    [0] CertificateList,
        delta-crl              [1] CertificateList,
        ocsp                   [2] OCSPResponse,
        other                  [3] OtherRevInfo }

 */

public class RevocationInfo extends ASN1Object implements ASN1Choice {

	public static final int crl = 0;
	public static final int deltaCrl = 1;
	public static final int ocsp = 2;
	public static final int other = 3;

	private ASN1Encodable obj;
	private int tag;

	public RevocationInfo(int tagNo, CertificateList crl) {
		this.tag = tagNo;
		this.obj = crl;
	}

	public RevocationInfo(OCSPResponse ocspResponse) {
		this.tag = RevocationInfo.ocsp;
		this.obj = ocspResponse;
	}

	public RevocationInfo(ASN1Encodable other) {
		this.tag = RevocationInfo.other;
		this.obj = other;
	}

	public RevocationInfo(int tagNo, ASN1Sequence obj) {
		this.tag = tagNo;
		this.obj = obj;
	}

	public static RevocationInfo getInstance(Object obj) {
		if (obj == null || obj instanceof RevocationInfo) {
			return (RevocationInfo)obj;
		}
		if (obj instanceof ASN1TaggedObject) {
			ASN1TaggedObject tagObj = (ASN1TaggedObject)obj;
			int tag = tagObj.getTagNo();
			switch (tag) {
			case RevocationInfo.crl:
				return new RevocationInfo(tag, ASN1Sequence.getInstance(tagObj, false));
			case RevocationInfo.deltaCrl:
				return new RevocationInfo(tag, ASN1Sequence.getInstance(tagObj, false));
			case RevocationInfo.ocsp:
				return new RevocationInfo(tag, ASN1Sequence.getInstance(tagObj, false));
			case RevocationInfo.other:
				return new RevocationInfo(tag, ASN1Sequence.getInstance(tagObj, false));
			default:
				throw new IllegalArgumentException("unknown tag: " + tag);
			}
		}
		if (obj instanceof byte[]) {
			try {
				return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
			} catch (IOException e) {
				throw new IllegalArgumentException("unable to parse encoded revocation info");
			}
		}
		throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
	}

	public static RevocationInfo getInstance(ASN1TaggedObject tagObj) {
		return RevocationInfo.getInstance(ASN1TaggedObject.getInstance(tagObj, false));
	}

	public int getTagNo() {
		return tag;
	}

	public ASN1Encodable getRevocationObject() {
		return obj;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if (obj != null) {
			v.add(new DERTaggedObject(false, tag, obj));
		}
		return new DERSequence(v); 
	}

}
