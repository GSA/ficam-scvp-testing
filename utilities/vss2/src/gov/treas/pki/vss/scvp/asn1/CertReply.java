/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2008-2015 keysupport.org
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package gov.treas.pki.vss.scvp.asn1;

import java.util.ArrayList;
import java.util.Iterator;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * This class is a representation of a CertReply.
 *
 * This is where most of the validation action is.  For each
 * certificate that is checked by the SCVP service, this
 * object contains the result of those checks, as well as
 * any other pertinent information defined by policy,
 * or requested by the client.
 *
 * TODO: Make other ASN.1 classes consistent with this one.
 * TODO: Fix Javadoc in this class.
 */
public class CertReply extends ASN1Object {

	public static CertReply getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static CertReply getInstance(Object obj) {
		if (obj == null || obj instanceof CertReply) {
			return (CertReply)obj;
		} else if (obj instanceof ASN1Sequence) {
			return new CertReply((ASN1Sequence)obj);
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	private CertReference cert;
	private Extensions certReplyExtensions;
	private ASN1GeneralizedTime nextUpdate;
	private ReplyChecks replyChecks;
	private ReplyStatus replyStatus;
	private ASN1GeneralizedTime replyValTime;
	private ReplyWantBacks replyWantBacks;
	private ASN1Sequence validationErrors;

	private CertReply(ASN1Sequence seq) {
		Iterator<ASN1Encodable> it = seq.iterator();
		/*
		 * Get the first 5 mandatory objects
		 */
		this.cert = CertReference.getInstance(it.next());
		ASN1Encodable next = it.next();
		if(!(next instanceof ASN1GeneralizedTime)) {
			this.replyStatus = ReplyStatus.getInstance(next);
			this.replyValTime = ASN1GeneralizedTime.getInstance(it.next());
		}
		else {
			this.replyStatus = new ReplyStatus(0);
			this.replyValTime = ASN1GeneralizedTime.getInstance(next);
		}
		this.replyChecks = ReplyChecks.getInstance(it.next());
		this.replyWantBacks = ReplyWantBacks.getInstance(it.next());
		/*
		 * Get the remaining optional objects
		 */
		while (it.hasNext()) {
			ASN1Encodable obj = it.next();
			if (obj instanceof DERTaggedObject) {
				DERTaggedObject tObj = (DERTaggedObject) obj;
				switch (tObj.getTagNo()) {
				case 0:
					this.validationErrors = ASN1Sequence.getInstance(tObj, false);
					break;
				case 1:
					this.nextUpdate = ASN1GeneralizedTime.getInstance(tObj, false);
					break;
				case 2:
					this.certReplyExtensions = Extensions.getInstance(tObj, false);
					break;
				default:
					throw new IllegalArgumentException("unknown tagged object in CertReply: " + obj.getClass().getName());
				}
			} else
				throw new IllegalArgumentException("unknown object in CertReply: " + obj.getClass().getName());
		}
	}

	public CertReply(CertReference cert, 
						ReplyStatus replyStatus, 
						ASN1GeneralizedTime replyValTime, 
						ReplyChecks replyChecks, 
						ReplyWantBacks replyWantBacks, 
						ASN1Sequence validationErrors, 
						ASN1GeneralizedTime nextUpdate, 
						Extensions certReplyExtensions) {
		this.cert = cert;
		this.replyStatus = replyStatus;
		this.replyValTime = replyValTime;
		this.replyChecks = replyChecks;
		this.replyWantBacks = replyWantBacks;
		this.validationErrors = validationErrors;
		this.nextUpdate = nextUpdate;
		this.certReplyExtensions = certReplyExtensions;
	}

	public CertReference getCertReference() {
		return cert;
	}

	public ASN1GeneralizedTime getNextUpdate() {
		return nextUpdate;
	}

	public ReplyChecks getReplyChecks() {
		return replyChecks;
	}

	public ReplyStatus getReplyStatus() {
		return replyStatus;
	}

	public ASN1GeneralizedTime getReplyValTime() {
		return replyValTime;
	}

	public ReplyWantBacks getReplyWantBacks() {
		return replyWantBacks;
	}

	public ASN1ObjectIdentifier[] getValidationErrors() {
		if (null != validationErrors) {
			ASN1Encodable[] elements = validationErrors.toArray();
			ArrayList<ASN1ObjectIdentifier> toReturn = new ArrayList<ASN1ObjectIdentifier>();
			for (ASN1Encodable element: elements) {
				toReturn.add(ASN1ObjectIdentifier.getInstance(element));
			}
			return toReturn.toArray(new ASN1ObjectIdentifier[toReturn.size()]);
		} else {
			return null;
		}
	}

	/**
	 * Method toASN1Primitive.
	 * 
	 * <pre>
	 *       CertReply ::= SEQUENCE {
	 *         cert                       CertReference,
	 *         replyStatus                ReplyStatus DEFAULT success,
	 *         replyValTime               GeneralizedTime,
	 *         replyChecks                ReplyChecks,
	 *         replyWantBacks             ReplyWantBacks,
	 *         validationErrors       [0] SEQUENCE SIZE (1..MAX) OF
	 *                                      OBJECT IDENTIFIER OPTIONAL,
	 *         nextUpdate             [1] GeneralizedTime OPTIONAL,
	 *         certReplyExtensions    [2] Extensions OPTIONAL }
	 * </pre>
	 * 
	 * @return ASN1Primitive
	 * @see org.bouncycastle.asn1.ASN1Encodable#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(cert);
		if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults() || !replyStatus.getValue().equals(ReplyStatus.SUCCESS)) {
			v.add(replyStatus);
		}
		v.add(replyValTime);
		v.add(replyChecks);
		v.add(replyWantBacks);
		if (validationErrors != null) {
			v.add(new DERTaggedObject(false, 0, validationErrors));
		}
		if (nextUpdate != null) {
			v.add(new DERTaggedObject(false, 1, nextUpdate));
		}
		if (certReplyExtensions != null) {
			v.add(new DERTaggedObject(false, 2, certReplyExtensions));
		}
		return new DERSequence(v); 
	}

}
