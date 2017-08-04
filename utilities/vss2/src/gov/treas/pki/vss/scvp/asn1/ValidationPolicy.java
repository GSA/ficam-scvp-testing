package gov.treas.pki.vss.scvp.asn1;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

/*
 */
public class ValidationPolicy extends ASN1Object {

	public static ValidationPolicy getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}
	public static ValidationPolicy getInstance(Object obj) {
		if (obj == null || obj instanceof ValidationPolicy) {
			return (ValidationPolicy) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ValidationPolicy((ASN1Sequence) obj);
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}
	private ASN1Sequence extendedKeyUsages = null;
	private ASN1Boolean inhibitAnyPolicy = null;
	private ASN1Boolean inhibitPolicyMapping = null;
	private ASN1Sequence keyUsages = null;
	private ASN1Boolean requireExplicitPolicy = null;
	private ASN1Sequence specifiedKeyUsages = null;
	private ASN1Sequence trustAnchors = null;
	private ASN1Sequence userPolicySet = null;
	private ValidationAlg validationAlg = null;
	private ValidationPolRef validationPolRef = null;

	private ValidationPolicy(ASN1Sequence seq) {
		Iterator<ASN1Encodable> it = seq.iterator();
		/*
		 * Get the first mandatory object
		 */
		this.validationPolRef = ValidationPolRef.getInstance(it.next());
		/*
		 * Get the remaining optional objects
		 */
		while (it.hasNext()) {
			ASN1Encodable obj = it.next();
			if (obj instanceof DERTaggedObject) {
				DERTaggedObject tObj = (DERTaggedObject) obj;
				switch (tObj.getTagNo()) {
				case 0:
					this.validationAlg = ValidationAlg.getInstance(tObj, false);
					break;
				case 1:
					this.userPolicySet = ASN1Sequence.getInstance(tObj, false);
					break;
				case 2:
					this.inhibitPolicyMapping = ASN1Boolean.getInstance(tObj, false);
					break;
				case 3:
					this.requireExplicitPolicy = ASN1Boolean.getInstance(tObj, false);
					break;
				case 4:
					this.inhibitAnyPolicy = ASN1Boolean.getInstance(tObj, false);
					break;
				case 5:
					this.trustAnchors = ASN1Sequence.getInstance(tObj, false);
					break;
				case 6:
					this.keyUsages = ASN1Sequence.getInstance(tObj, false);
					break;
				case 7:
					this.extendedKeyUsages = ASN1Sequence.getInstance(tObj, false);
					break;
				case 8:
					this.specifiedKeyUsages = ASN1Sequence.getInstance(tObj, false);
					break;
				default:
					throw new IllegalArgumentException(
							"unknown tagged object in CertReply: " + obj.getClass().getName());
				}
			} else
				throw new IllegalArgumentException("unknown object in CertReply: " + obj.getClass().getName());
		}
	}

	public ValidationPolicy(ValidationPolRef validationPolRef, ValidationAlg validationAlg, ASN1Sequence userPolicySet,
			ASN1Boolean inhibitPolicyMapping, ASN1Boolean requireExplicitPolicy, ASN1Boolean inhibitAnyPolicy,
			ASN1Sequence trustAnchors, ASN1Sequence keyUsages, ASN1Sequence extendedKeyUsages,
			ASN1Sequence specifiedKeyUsages) {
		this.validationPolRef = validationPolRef;
		this.validationAlg = validationAlg;
		this.userPolicySet = userPolicySet;
		this.inhibitPolicyMapping = inhibitPolicyMapping;
		this.requireExplicitPolicy = requireExplicitPolicy;
		this.inhibitAnyPolicy = inhibitAnyPolicy;
		this.trustAnchors = trustAnchors;
		this.keyUsages = keyUsages;
		this.extendedKeyUsages = extendedKeyUsages;
		this.specifiedKeyUsages = specifiedKeyUsages;
	}

	/*
	 *       ValidationPolicy ::= SEQUENCE {
 	 *          validationPolRef          ValidationPolRef,
 	 *          validationAlg         [0] ValidationAlg OPTIONAL,
 	 *          userPolicySet         [1] SEQUENCE SIZE (1..MAX) OF OBJECT
 	 *          IDENTIFIER OPTIONAL,
 	 *          inhibitPolicyMapping  [2] BOOLEAN OPTIONAL,
 	 *          requireExplicitPolicy [3] BOOLEAN OPTIONAL,
 	 *          inhibitAnyPolicy      [4] BOOLEAN OPTIONAL,
 	 *          trustAnchors          [5] TrustAnchors OPTIONAL,
 	 *          keyUsages             [6] SEQUENCE OF KeyUsage OPTIONAL,
 	 *          extendedKeyUsages     [7] SEQUENCE OF KeyPurposeId OPTIONAL,
	 *          specifiedKeyUsages    [8] SEQUENCE OF KeyPurposeId OPTIONAL }
	 * 
	 * (non-Javadoc)
	 * @see org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
	 */
	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(validationPolRef);
		if (validationAlg != null) {
			v.add(new DERTaggedObject(false, 0, validationAlg));
		}
		if (userPolicySet != null) {
			v.add(new DERTaggedObject(false, 1, userPolicySet));
		}
		if (inhibitPolicyMapping != null) {
			v.add(new DERTaggedObject(false, 2, inhibitPolicyMapping));
		}
		if (requireExplicitPolicy != null) {
			v.add(new DERTaggedObject(false, 3, requireExplicitPolicy));
		}
		if (inhibitAnyPolicy != null) {
			v.add(new DERTaggedObject(false, 4, inhibitAnyPolicy));
		}
		if (trustAnchors != null) {
			v.add(new DERTaggedObject(false, 5, trustAnchors));
		}
		if (keyUsages != null) {
			v.add(new DERTaggedObject(false, 6, keyUsages));
		}
		if (extendedKeyUsages != null) {
			v.add(new DERTaggedObject(false, 7, extendedKeyUsages));
		}
		if (specifiedKeyUsages != null) {
			v.add(new DERTaggedObject(false, 7, specifiedKeyUsages));
		}
		return new DERSequence(v);
	}

	public ASN1Sequence getExtendedKeyUsages() {
		return extendedKeyUsages;
	}

	public ASN1Boolean getInhibitAnyPolicy() {
		return inhibitAnyPolicy;
	}

	public ASN1Boolean getInhibitPolicyMapping() {
		return inhibitPolicyMapping;
	}

	public ASN1Sequence getKeyUsages() {
		return keyUsages;
	}

	public ASN1Boolean getRequireExplicitPolicy() {
		return requireExplicitPolicy;
	}

	public ASN1Sequence getSpecifiedKeyUsages() {
		return specifiedKeyUsages;
	}

	public ASN1Sequence getTrustAnchors() {
		return trustAnchors;
	}

	public ASN1Sequence getUserPolicySet() {
		return userPolicySet;
	}

	public ValidationAlg getValidationAlg() {
		return validationAlg;
	}

	public ValidationPolRef getValidationPolRef() {
		return validationPolRef;
	}
}
