package gov.treas.pki.vss.scvp.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class RevocationInfos extends ASN1Object {

	private final RevocationInfo[] revocationInfo;

	public static RevocationInfos getInstance(Object obj) {
		if (obj instanceof RevocationInfos) {
			return (RevocationInfos) obj;
		}
		if (obj != null) {
			return new RevocationInfos(ASN1Sequence.getInstance(obj));
		}
		return null;
	}

	public static RevocationInfos getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	/**
	 * Construct a RevocationInfos object containing one RevocationInfo.
	 * 
	 * @param revocationInfo
	 *            the name to be contained.
	 */
	public RevocationInfos(RevocationInfo revocationInfo) {
		this.revocationInfo = new RevocationInfo[] { revocationInfo };
	}

	public RevocationInfos(RevocationInfo[] revocationInfo) {
		this.revocationInfo = revocationInfo;
	}

	private RevocationInfos(ASN1Sequence seq) {
		this.revocationInfo = new RevocationInfo[seq.size()];
		for (int i = 0; i != seq.size(); i++) {
			revocationInfo[i] = RevocationInfo.getInstance(seq.getObjectAt(i));
		}
	}

	public RevocationInfo[] getRevocationInfos() {
		RevocationInfo[] tmp = new RevocationInfo[revocationInfo.length];
		System.arraycopy(revocationInfo, 0, tmp, 0, revocationInfo.length);
		return tmp;
	}

	/**
	 * Produce an object suitable for an ASN1OutputStream.
	 * 
	 * <pre>
	 * RevocationInfos ::= SEQUENCE SIZE {1..MAX} OF RevocationInfo
	 * </pre>
	 */
	public ASN1Primitive toASN1Primitive() {
		return new DERSequence(revocationInfo);
	}

}