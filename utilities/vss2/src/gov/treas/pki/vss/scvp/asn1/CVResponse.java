package gov.treas.pki.vss.scvp.asn1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;

public class CVResponse extends ASN1Object {

	public static final ASN1ObjectIdentifier idCtScvpCertValResponse = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.11").intern();

	public static CVResponse getInstance(Object obj) {
		if (obj == null || obj instanceof CVResponse) {
			return (CVResponse)obj;
		} else if (obj instanceof ASN1Sequence) {
			return new CVResponse((ASN1Sequence)obj);
		} else if (obj instanceof byte[]) {
			try {
				return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
			} catch (IOException e) {
				throw new IllegalArgumentException("unable to parse encoded revocation info");
			}
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	private Extensions cvResponseExtensions = null;
	private ASN1Integer cvResponseVersion = null;
	private ASN1GeneralizedTime producedAt = null;
	private ASN1Sequence replyObjects = null;
	private GeneralNames requestorName = null;
	private GeneralNames requestorRef = null;
	private ASN1OctetString requestorText = null;
	private RequestReference requestRef = null;
	private ASN1OctetString respNonce = null;
	private ResponseStatus responseStatus = null;
	private ValidationPolicy respValidationPolicy = null;
	private ASN1Integer serverConfigurationID = null;
	private ASN1OctetString serverContextInfo = null;

	public CVResponse(ASN1Integer cvResponseVersion, 
						ASN1Integer serverConfigurationID, 
						ASN1GeneralizedTime producedAt, 
						ResponseStatus responseStatus, 
						ValidationPolicy respValidationPolicy, 
						RequestReference requestRef, 
						GeneralNames requestorRef, 
						GeneralNames requestorName, 
						ASN1Sequence replyObjects, 
						ASN1OctetString respNonce, 
						ASN1OctetString serverContextInfo, 
						Extensions cvResponseExtensions,
						ASN1OctetString requestorText) {
		this.cvResponseVersion = cvResponseVersion; 
		this.serverConfigurationID = serverConfigurationID;
 		this.producedAt = producedAt;
		this.responseStatus = responseStatus;
		this.respValidationPolicy = respValidationPolicy;
		this.requestRef = requestRef;
		this.requestorRef = requestorRef;
		this.requestorName = requestorName;
		this.replyObjects = replyObjects;
		this.respNonce = respNonce;
		this.serverContextInfo = serverContextInfo;
		this.cvResponseExtensions = cvResponseExtensions;
		this.requestorText = requestorText;
	}

	private CVResponse(ASN1Sequence seq) {
		Iterator<ASN1Encodable> it = seq.iterator();
		/*
		 * Get the first 4 mandatory objects
		 */
		this.cvResponseVersion = ASN1Integer.getInstance(it.next());
		this.serverConfigurationID = ASN1Integer.getInstance(it.next());
		this.producedAt = ASN1GeneralizedTime.getInstance(it.next());
		this.responseStatus = ResponseStatus.getInstance(it.next());
		/*
		 * Get the remaining optional objects
		 */
		while (it.hasNext()) {
			ASN1Encodable obj = it.next();
			if (obj instanceof DERTaggedObject) {
				DERTaggedObject tObj = (DERTaggedObject) obj;
				switch (tObj.getTagNo()) {
				case 0:
					this.respValidationPolicy = ValidationPolicy.getInstance(tObj, false);
					break;
				case 1:
					this.requestRef = RequestReference.getInstance(tObj, true);
					break;
				case 2:
					this.requestorRef = GeneralNames.getInstance(tObj, false);
					break;
				case 3:
					this.requestorName = GeneralNames.getInstance(tObj, false);
					break;
				case 4:
					this.replyObjects = ASN1Sequence.getInstance(tObj, false);
					break;
				case 5:
					this.respNonce = ASN1OctetString.getInstance(tObj, false);
					break;
				case 6:
					this.serverContextInfo = ASN1OctetString.getInstance(tObj, false);
					break;
				case 7:
					this.cvResponseExtensions = Extensions.getInstance(tObj, false);
					break;
				case 8:
					this.requestorText = ASN1OctetString.getInstance(tObj, false);
					break;
				default:
					throw new IllegalArgumentException("unknown tagged object in CertReply: " + obj.getClass().getName());
				}
			} else
				throw new IllegalArgumentException("unknown object in CertReply: " + obj.getClass().getName());
		}
	}

	/*
	 *       CVResponse ::= SEQUENCE {
	        cvResponseVersion         INTEGER,
	        serverConfigurationID     INTEGER,
	        producedAt                GeneralizedTime,
	        responseStatus            ResponseStatus,
	        respValidationPolicy  [0] RespValidationPolicy OPTIONAL,
	        requestRef            [1] RequestReference OPTIONAL,
	        requestorRef          [2] GeneralNames OPTIONAL,
	        requestorName         [3] GeneralNames OPTIONAL,
	        replyObjects          [4] ReplyObjects OPTIONAL,
	        respNonce             [5] OCTET STRING OPTIONAL,
	        serverContextInfo     [6] OCTET STRING OPTIONAL,
	        cvResponseExtensions  [7] Extensions OPTIONAL,
	        requestorText         [8] UTF8String (SIZE (1..256)) OPTIONAL }

*       ReplyObjects ::= SEQUENCE SIZE (1..MAX) OF CertReply
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(cvResponseVersion);
		v.add(serverConfigurationID);
		v.add(producedAt);
		v.add(responseStatus);
		if (respValidationPolicy != null) {
			v.add(new DERTaggedObject(false, 0, respValidationPolicy));
		}
		if (requestRef != null) {
			v.add(new DERTaggedObject(false, 1, requestRef));
		}
		if (requestorRef != null) {
			v.add(new DERTaggedObject(false, 2, requestorRef));
		}
		if (requestorName != null) {
			v.add(new DERTaggedObject(false, 3, requestorName));
		}
		if (replyObjects != null) {
			v.add(new DERTaggedObject(false, 4, replyObjects));
		}
		if (respNonce != null) {
			v.add(new DERTaggedObject(false, 5, respNonce));
		}
		if (serverContextInfo != null) {
			v.add(new DERTaggedObject(false, 6, serverContextInfo));
		}
		if (cvResponseExtensions != null) {
			v.add(new DERTaggedObject(false, 7, cvResponseExtensions));
		}
		if (requestorText != null) {
			v.add(new DERTaggedObject(false, 8, requestorText));
		}
		return new DERSequence(v); 
	}

	public ASN1Integer getResponseVersion() {
		return this.cvResponseVersion;
	}

	public ASN1Integer getServerConfigurationID() {
		return this.serverConfigurationID;
	}

	public ASN1GeneralizedTime getProducedAt() {
		return this.producedAt;
	}

	public ResponseStatus getResponseStatus() {
		return this.responseStatus;
	}

	public ValidationPolicy getResponseValidationPolicy() {
		return this.respValidationPolicy;
	}

	public RequestReference getRequestRef() {
		return this.requestRef;
	}

	public GeneralNames getRequestorRef() {
		return this.requestorRef;
	}

	public GeneralNames getRequestorName() {
		return this.requestorName;
	}

	public List<CertReply> getReplyObjects() {
		ArrayList<CertReply> repObj = new ArrayList<CertReply>();
		if(null != this.replyObjects) {
			for (ASN1Encodable obj : this.replyObjects.toArray()) {
				repObj.add(CertReply.getInstance(obj));
			}
		}
		return repObj;
	}

	public ASN1OctetString getRespNonce() {
		return this.respNonce;
	}

	public ASN1OctetString getServerContextInfo() {
		return this.serverContextInfo;
	}

	public Extensions getResponseExtensions() {
		return this.cvResponseExtensions;
	}

	public ASN1OctetString getRequestorText() {
		return this.requestorText;
	}

}
