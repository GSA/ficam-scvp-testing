package gov.treas.pki.vss.scvp.asn1;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import org.bouncycastle.asn1.*;

public class ResponseStatus extends ASN1Object {

	private CVStatusCode statusCode = null;
	private DERUTF8String errorMessage = null;

	private ResponseStatus(ASN1Sequence seq) {
		if (seq.size() < 0 || seq.size() > 2) {
			throw new IllegalArgumentException("Bad sequence size: " + seq.size());
		}
		if(seq.size() == 0) {
			this.statusCode = new CVStatusCode(0);
			return;
		}
		this.statusCode = CVStatusCode.getInstance(seq.getObjectAt(0));
		if (seq.size() == 2) {
			//this.errorMessage = DERUTF8String.getInstance(seq.getObjectAt(1));

			ASN1TaggedObject s = DERTaggedObject.getInstance(seq.getObjectAt(1));
			this.errorMessage = DERUTF8String.getInstance(s, false);
		} else {
			this.errorMessage = null;
		}
	}

	public ResponseStatus(CVStatusCode statusCode, DERUTF8String errorMessage) {
		this.statusCode = statusCode;
		this.errorMessage = errorMessage;
	}

	public static ResponseStatus getInstance(Object obj) {
		if (obj == null || obj instanceof ResponseStatus) {
			return (ResponseStatus) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ResponseStatus(ASN1Sequence.getInstance(obj));
		}
		throw new IllegalArgumentException("unknown object in CertReply: " + obj.getClass().getName());
	}

	/*
	 * <pre>

 *       ResponseStatus ::= SEQUENCE {
        statusCode            CVStatusCode DEFAULT  okay,
        errorMessage          UTF8String OPTIONAL }
        	 * </pre>

        
	(non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || !statusCode.getValue().equals(CVStatusCode.OKAY)) {
			v.add(statusCode);
		}
		if (errorMessage!= null) {
			v.add(errorMessage);
		}
		return new DERSequence(v);
	}

	public CVStatusCode getStatusCode() {
		return this.statusCode;
	}

	public DERUTF8String getErrorMessage() {
		return this.errorMessage;
	}

}
