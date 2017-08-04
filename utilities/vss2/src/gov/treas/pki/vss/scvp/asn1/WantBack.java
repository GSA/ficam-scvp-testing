package gov.treas.pki.vss.scvp.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class WantBack extends ASN1Object {

	/**
	 * id-swb-pkc-cert: The certificate that was the subject of the request;
	 */
	public static final ASN1ObjectIdentifier idSwbPkcCert = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.10").intern();
	/**
	 * id-swb-pkc-best-cert-path: The certification path built for the
	 * certificate including the certificate that was validated;
	 */
	public static final ASN1ObjectIdentifier idSwbPkcBestCertPath = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.1");
	/**
	 * id-swb-pkc-revocation-info: Proof of revocation status for each
	 * certificate in the certification path;
	 */
	public static final ASN1ObjectIdentifier idSwbPkcRevocationInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.2");
	/**
	 * id-swb-pkc-public-key-info: The public key from the certificate that was
	 * the subject of the request;
	 */
	public static final ASN1ObjectIdentifier idSwbPkcPublicKeyInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.4");
	/**
	 * id-swb-pkc-all-cert-paths: A set of certification paths for the
	 * certificate that was the subject of the request;
	 */
	public static final ASN1ObjectIdentifier idSwbPkcAllCertPaths = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.12");
	/**
	 * id-swb-pkc-ee-revocation-info: Proof of revocation status for the end
	 * entity certificate in the certification path; and
	 */
	public static final ASN1ObjectIdentifier idSwbPkcEeRevocationInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.13");
	/**
	 * id-swb-pkc-CAs-revocation-info: Proof of revocation status for each CA
	 * certificate in the certification path.
	 */
	public static final ASN1ObjectIdentifier idSwbPkcCAsRevocationInfo = new ASN1ObjectIdentifier(
			"1.3.6.1.5.5.7.18.14");

	/**
	 * Field value.
	 */
	private ASN1Sequence value;

	public WantBack(Enumeration<ASN1ObjectIdentifier> wantBack) {
		final ASN1EncodableVector v = new ASN1EncodableVector();
		while (wantBack.hasMoreElements()) {
			v.add(wantBack.nextElement());
		}
		this.value = new DERSequence(v);
	}

	private WantBack(ASN1Sequence value) {
		this.value = value;
	}

	public static WantBack getInstance(Object obj) {
		if (obj instanceof WantBack) {
			return (WantBack) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new WantBack(ASN1Sequence.getInstance(obj));
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
