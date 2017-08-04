package gov.treas.pki.vss.scvp.asn1;

import java.io.IOException;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/*
 * TODO: Migrate OID constants to a consolidated class?
 */
public class CertChecks extends ASN1Object {

	public final static ASN1ObjectIdentifier idStcBuildPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.1").intern();
	public final static ASN1ObjectIdentifier idStcBuildValidPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.2").intern();
	public final static ASN1ObjectIdentifier idStcBuildStatusCheckedPkcPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.3").intern();
	public final static ASN1ObjectIdentifier idStcBuildAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.4").intern();
	public final static ASN1ObjectIdentifier idStcBuildValidAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.5").intern();
	public final static ASN1ObjectIdentifier idStcBuildStatusCheckedAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.6").intern();
	public final static ASN1ObjectIdentifier idStcStatusCheckAcAndBuildStatusCheckedAaPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.17.7").intern();

	/**
	 * Field value.
	 */
	private ASN1Sequence value;

	public CertChecks(Enumeration<ASN1ObjectIdentifier> certChecks) {
		final ASN1EncodableVector v = new ASN1EncodableVector();
		while (certChecks.hasMoreElements()) {
			v.add(certChecks.nextElement());
		}
		this.value = new DERSequence(v);
	}

	private CertChecks(ASN1Sequence value) {
		this.value = value;
	}

	/**
	 * Method getInstance.
	 * @param obj Object
	 * @return CertChecks
	 * @throws IOException
	 */
	public static CertChecks getInstance(Object obj) {
		if (obj instanceof CertChecks) {
			return (CertChecks) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new CertChecks(ASN1Sequence.getInstance(obj));
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());

	}

	public Enumeration<?> getValues() {
		return this.value.getObjects();
	}

	/**
	 * Method toASN1Primitive.
	 * @return ASN1Primitive
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		return this.value;
	}

	public ASN1Encodable[] toArray() {
		return this.value.toArray();
	}

}
