package gov.treas.pki.vss.scvp.asn1;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.IssuerSerial;

/*
 *  SCVPCertID ::= SEQUENCE {
       certHash        OCTET STRING,
       issuerSerial    SCVPIssuerSerial,
       hashAlgorithm   AlgorithmIdentifier DEFAULT { algorithm sha-1 } }

 */
public class SCVPCertID extends ASN1Object {
	
	private ASN1OctetString certHash = null;
	private IssuerSerial issuerSerial = null;
	private AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));

	public SCVPCertID() {
		// TODO Auto-generated constructor stub
	}

	/*
	public static SCVPCertID getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(DERTaggedObject.getInstance(obj, explicit));
	}
	*/

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(certHash);
		v.add(issuerSerial);
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || "1.3.14.3.2.26".equals(hashAlgorithm.getAlgorithm().getId())) {
			v.add(hashAlgorithm);
		}
		return new DERSequence(v);
	}

	public ASN1OctetString getCertHash() {
		return certHash;
	}
}
