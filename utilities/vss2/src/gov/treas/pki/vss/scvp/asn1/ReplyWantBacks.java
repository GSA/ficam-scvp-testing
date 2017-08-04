/**
 * 
 */
package gov.treas.pki.vss.scvp.asn1;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class ReplyWantBacks extends ASN1Object {

	private Hashtable<ASN1ObjectIdentifier, ReplyWantBack> replyWantbacks = new Hashtable<ASN1ObjectIdentifier, ReplyWantBack>();
	private Vector<ASN1ObjectIdentifier> ordering = new Vector<ASN1ObjectIdentifier>();

	public static ReplyWantBacks getInstance(ASN1TaggedObject obj, boolean explicit) {
		return getInstance(ASN1Sequence.getInstance(obj, explicit));
	}

	public static ReplyWantBacks getInstance(Object obj) {
		if (obj == null || obj instanceof ReplyWantBacks) {
			return (ReplyWantBacks)obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ReplyWantBacks((ASN1Sequence)obj);
		}
		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
	}

	/**
	 * Constructor from ASN1Sequence.
	 * <p>
	 * The replyWantbacks are a list of constructed sequences, either with (OID,
	 * OctetString) or (OID, Boolean, OctetString)
	 * </p>
	 */
	private ReplyWantBacks(ASN1Sequence seq) {
		Enumeration<?> e = seq.getObjects();
		while (e.hasMoreElements()) {
			ReplyWantBack rwb = ReplyWantBack.getInstance(e.nextElement());
			replyWantbacks.put(rwb.getWb(), rwb);
			ordering.addElement(rwb.getWb());
		}
	}

	/**
	 * Base Constructor
	 *
	 * @param ReplyWantBack
	 *            a single ReplyWantBack.
	 */
	public ReplyWantBacks(ReplyWantBack replyWantBack) {
		this.ordering.addElement(replyWantBack.getWb());
		this.replyWantbacks.put(replyWantBack.getWb(), replyWantBack);
	}

	/**
	 * Base Constructor
	 *
	 * @param replyWantbacks
	 *            an array of replyWantbacks.
	 */
	public ReplyWantBacks(ReplyWantBack[] replyWantBacks) {
		for (int i = 0; i != replyWantBacks.length; i++) {
			ReplyWantBack replyWantBack = replyWantBacks[i];
			this.ordering.addElement(replyWantBack.getWb());
			this.replyWantbacks.put(replyWantBack.getWb(), replyWantBack);
		}
	}

	/**
	 * return an Enumeration of the ReplyWantBack's object ids.
	 */
	public Enumeration<ASN1ObjectIdentifier> oids() {
		return ordering.elements();
	}

	/**
	 * return the ReplyWantBack represented by the object identifier passed in.
	 *
	 * @return the ReplyWantBack if it's present, null otherwise.
	 */
	public ReplyWantBack getReplyWantBack(ASN1ObjectIdentifier oid) {
		return (ReplyWantBack) replyWantbacks.get(oid);
	}

	/**
	 * return the parsed value of the ReplyWantBack represented by the object
	 * identifier passed in.
	 *
	 * @return the parsed value of the ReplyWantBack if it's present, null
	 *         otherwise.
	 */
	public ASN1Encodable getReplyWantBackParsedValue(ASN1ObjectIdentifier oid) {
		ReplyWantBack replyWantBack = this.getReplyWantBack(oid);
		if (replyWantBack != null) {
			return replyWantBack.getParsedValue();
		}
		return null;
	}

	/**
	 * <pre>
	 *     ReplyWantBacks ::= SEQUENCE OF ReplyWantBack
	 *
	 *     ReplyWantBack ::= SEQUENCE {
	 *        wb                         OBJECT IDENTIFIER,
	 *        value                      OCTET STRING
	 *     }
	 * </pre>
	 */
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector vec = new ASN1EncodableVector();
		Enumeration<ASN1ObjectIdentifier> e = ordering.elements();
		while (e.hasMoreElements()) {
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
			ReplyWantBack replyWantBack = (ReplyWantBack) replyWantbacks.get(oid);
			vec.add(replyWantBack);
		}
		return new DERSequence(vec);
	}

	public boolean equivalent(ReplyWantBacks other) {
		if (replyWantbacks.size() != other.replyWantbacks.size()) {
			return false;
		}
		Enumeration<ASN1ObjectIdentifier> e1 = replyWantbacks.keys();
		while (e1.hasMoreElements()) {
			Object key = e1.nextElement();
			if (!replyWantbacks.get(key).equals(other.replyWantbacks.get(key))) {
				return false;
			}
		}
		return true;
	}

	public ASN1ObjectIdentifier[] getReplyWantBackOIDs() {
		return toOidArray(ordering);
	}

	private ASN1ObjectIdentifier[] toOidArray(Vector<ASN1ObjectIdentifier> oidVec) {
		ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[oidVec.size()];
		for (int i = 0; i != oids.length; i++) {
			oids[i] = (ASN1ObjectIdentifier) oidVec.elementAt(i);
		}
		return oids;
	}

}