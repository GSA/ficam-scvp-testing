package gov.treas.pki.vss.scvp.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/*
 * 

      ReplyStatus ::= ENUMERATED {
          success                    (0),
          malformedPKC               (1),
          malformedAC                (2),
          unavailableValidationTime  (3),
          referenceCertHashFail      (4),
          certPathConstructFail      (5),
          certPathNotValid           (6),
          certPathNotValidNow        (7),
          wantBackUnsatisfied        (8) }

   The meanings of the various ReplyStatus values are:

   0 Success: all checks were performed successfully.
   1 Failure: the public key certificate was malformed.
   2 Failure: the attribute certificate was malformed.
   3 Failure: historical data for the requested validation time is not
      available.
   4 Failure: the server could not locate the reference certificate or
      the referenced certificate did not match the hash value provided.
   5 Failure: no certification path could be constructed.
   6 Failure: the constructed certification path is not valid with
      respect to the validation policy.
   7 Failure: the constructed certification path is not valid with
      respect to the validation policy, but a query at a later time may
      be successful.
   8 Failure: all checks were performed successfully; however, one or
      more of the wantBacks could not be satisfied.

   Codes 1 and 2 are used to tell the client that the request was
   properly formed, but the certificate in question was not.  This is
   especially useful to clients that do not parse certificates.

   Code 7 is used to tell the client that a valid certification path was
   found with the exception that a certificate in the path is on hold,
   current revocation information is unavailable, or the validation time
   precedes the notBefore time in one or more certificates in the path.

   For codes 1, 2, 3, and 4, the replyChecks and replyWantBacks items
   are not populated (i.e., they MUST be an empty sequence).  For codes
   5, 6, 7, and 8, replyChecks MUST include an entry corresponding to
   each check in the request; the replyWantBacks item is not populated.

 */
public class ReplyStatus extends ASN1Object {
	
	public static final int SUCCESS = 0;
	public static final int MALFORMEDPKC = 1;
	public static final int MALFORMEDAC = 2;
	public static final int UNAVAILABLEVALIDATIONTIME = 3;
	public static final int REFERENCECERTHASHFAIL = 4;
	public static final int CERTPATHCONSTRUCTFAIL = 5;
	public static final int CERTPATHNOTVALID = 6;
	public static final int CERTPATHNOTVALIDNOW = 7;
	public static final int WANTBACKUNSATISFIED = 8;

	private ASN1Enumerated value;

	public ReplyStatus(int value) {
		this(new ASN1Enumerated(value));
	}

	private ReplyStatus(ASN1Enumerated value) {
		this.value = value;
	}

	public static ReplyStatus getInstance(Object obj) {
		if (obj == null || obj instanceof ReplyStatus) {
			return (ReplyStatus) obj;
		} else if (obj instanceof ASN1Enumerated) {
			return new ReplyStatus(ASN1Enumerated.getInstance(obj));
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	public BigInteger getValue() {
		return value.getValue();
	}

	public ASN1Primitive toASN1Primitive() {
		return value;
	}
}