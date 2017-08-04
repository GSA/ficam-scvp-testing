package gov.treas.pki.vss.scvp.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/*
 * 
      CVStatusCode ::= ENUMERATED {
        okay                               (0),
        skipUnrecognizedItems              (1),
        tooBusy                           (10),
        invalidRequest                    (11),
        internalError                     (12),
        badStructure                      (20),
        unsupportedVersion                (21),
        abortUnrecognizedItems            (22),
        unrecognizedSigKey                (23),
        badSignatureOrMAC                 (24),
        unableToDecode                    (25),
        notAuthorized                     (26),
        unsupportedChecks                 (27),
        unsupportedWantBacks              (28),
        unsupportedSignatureOrMAC         (29),
        invalidSignatureOrMAC             (30),
        protectedResponseUnsupported      (31),
        unrecognizedResponderName         (32),
        relayingLoop                      (40),
        unrecognizedValPol                (50),
        unrecognizedValAlg                (51),
        fullRequestInResponseUnsupported  (52),
        fullPolResponseUnsupported        (53),
        inhibitPolicyMappingUnsupported   (54),
        requireExplicitPolicyUnsupported  (55),
        inhibitAnyPolicyUnsupported       (56),
        validationTimeUnsupported         (57),
        unrecognizedCritQueryExt          (63),
        unrecognizedCritRequestExt        (64) }

   The CVStatusCode values have the following meaning:

    0 The request was fully processed.
    1 The request included some unrecognized non-critical extensions;
      however, processing was able to continue ignoring them.
   10 Too busy; try again later.
   11 The server was able to decode the request, but there was some
      other problem with the request.
   12 An internal server error occurred.
   20 The structure of the request was wrong.
   21 The version of request is not supported by this server.
   22 The request included unrecognized items, and the server was not
      able to continue processing.
   23 The server could not validate the key used to protect the
      request.
   24 The signature or message authentication code did not match the
      body of the request.
   25 The encoding was not understood.
   26 The request was not authorized.
   27 The request included unsupported checks items, and the server was
      not able to continue processing.
   28 The request included unsupported wantBack items, and the server
      was not able to continue processing.
   29 The server does not support the signature or message
      authentication code algorithm used by the client to protect the
      request.
   30 The server could not validate the client's signature or message
      authentication code on the request.
   31 The server could not generate a protected response as requested
      by the client.
   32 The server does not have a certificate matching the requested
      responder name.
   40 The request was previously relayed by the same server.
   50 The request contained an unrecognized validation policy
      reference.
   51 The request contained an unrecognized validation algorithm OID.
   52 The server does not support returning the full request in the
      response.
   53 The server does not support returning the full validation policy
      by value in the response.
   54 The server does not support the requested value for inhibit
      policy mapping.
   55 The server does not support the requested value for require
      explicit policy.
   56 The server does not support the requested value for inhibit
      anyPolicy.
   57 The server only validates requests using current time.
   63 The query item in the request contains a critical extension whose
      OID is not recognized.
   64 The request contains a critical request extension whose OID is
      not recognized.


 */
public class CVStatusCode extends ASN1Object {
	
	public static final int OKAY = 0;
	public static final int SKIPUNRECOGNIZEDITEMS = 1;
	public static final int TOOBUSY = 10;
	public static final int INVALIDREQUEST = 11;
	public static final int INTERNALERROR = 12;
	public static final int BADSTRUCTURE = 20;
	public static final int UNSUPPORTEDVERSION = 21;
	public static final int ABORTUNRECOGNIZEDITEMS = 22;
	public static final int UNRECOGNIZEDSIGKEY = 23;
	public static final int BADSIGNATUREORMAC = 24;
	public static final int UNABLETODECODE = 25;
	public static final int NOTAUTHORIZED = 26;
	public static final int UNSUPPORTEDCHECKS = 27;
	public static final int UNSUPPORTEDWANTBACKS = 28;
	public static final int UNSUPPORTEDSIGNATUREORMAC = 29;
	public static final int INVALIDSIGNATUREORMAC = 30;
	public static final int PROTECTEDRESPONSEUNSUPPORTED = 31;
	public static final int UNRECOGNIZEDRESPONDERNAME = 32;
	public static final int RELAYINGLOOP = 40;
	public static final int UNRECOGNIZEDVALPOL = 50;
	public static final int UNRECOGNIZEDVALALG = 51;
	public static final int FULLREQUESTINRESPONSEUNSUPPORTED = 52;
	public static final int FULLPOLRESPONSEUNSUPPORTED = 53;
	public static final int INHIBITPOLICYMAPPINGUNSUPPORTED = 54;
	public static final int REQUIREEXPLICITPOLICYUNSUPPORTED = 55;
	public static final int INHIBITANYPOLICYUNSUPPORTED = 56;
	public static final int VALIDATIONTIMEUNSUPPORTED = 57;
	public static final int UNRECOGNIZEDCRITQUERYEXT = 63;
	public static final int UNRECOGNIZEDCRITREQUESTEXT = 64;

	private ASN1Enumerated value;
	

	public CVStatusCode(int value) {
		this(new ASN1Enumerated(value));
	}

	private CVStatusCode(ASN1Enumerated value) {
		this.value = value;
	}

	public static CVStatusCode getInstance(Object obj) {
		if (obj instanceof CVStatusCode) {
			return (CVStatusCode) obj;
		} else if (obj != null) {
			return new CVStatusCode(ASN1Enumerated.getInstance(obj));
		}
		return null;
	}

	public BigInteger getValue() {
		return value.getValue();
	}

	public ASN1Primitive toASN1Primitive() {
		return value;
	}
}