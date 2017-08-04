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

import java.io.IOException;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * @author tejohnson
 * 
 * This class is a representation of a ReplyCheck.
 * 
 * <pre>
 *       ReplyCheck ::= SEQUENCE {
 *         check                      OBJECT IDENTIFIER,
 *         status                     INTEGER DEFAULT 0 }
 * </pre>
 *
 * This code is intended to be a model class for this overall API,
 * as it performs basic bounds checking, and allows us to encode
 * as well as decode.
 * @version $Revision: 1.0 $
 */
public class ReplyCheck extends ASN1Object {

	/*
	 * Memory representation of this object
	 */
	/**
	 * Field value.
	 */
	private ASN1Sequence value;
	/**
	 * Field check.
	 */
	private ASN1ObjectIdentifier check;
	/**
	 * Field status.
	 */
	private ASN1Integer status;

	/*
	 * The MIN and MAX size of this object
	 */
	/**
	 * Field MIN_OBJ.
	 */
	private int MIN_OBJ = 1;
	/**
	 * Field MAX_OBJ.
	 */
	private int MAX_OBJ = 2;

	/*
	 * Static helpers supporting the ASN.1
	 */
	/**
	 * Field STATUS_DEFAULT.
	 */
	public static final ASN1Integer STATUS_DEFAULT = new ASN1Integer(0);

	/**
	 * 
	 * @param check ASN1ObjectIdentifier
	 * @param status ASN1Integer
	 */
	public ReplyCheck(ASN1ObjectIdentifier check, ASN1Integer status) {
		
		final ASN1EncodableVector v;

		this.check = check;
		if (null != status) {
			this.status = status;
		} else if(!VSSGlobalProperties.getInstance().getDerEncodeDefaults()) {
			this.status = ReplyCheck.STATUS_DEFAULT;
		}
		/*
		 * Now construct the overall value, where we encode explicit
		 * with no implied default values.  We are working with DER,
		 * not BER.
		 */
		v = new ASN1EncodableVector();
		v.add(this.check);
		v.add(this.value);
		this.value = new DERSequence(v);
	}

	/**
	 * Constructor for ReplyCheck.
	 * @param value ASN1Sequence
	 * @throws IOException
	 */
	private ReplyCheck(ASN1Sequence value) throws IOException {
		/*
		 * Check the object size
		 */
		if (value.size() > MAX_OBJ || value.size() < MIN_OBJ) {
			throw new IOException("Invalid ReplyCheck syntax encountered");
		} else {
			this.value = value;
			this.check = (ASN1ObjectIdentifier) value.getObjectAt(0);
			/*
			 * We could encounter a default, so check
			 */
			if (MIN_OBJ != value.size()) {
				this.status = (ASN1Integer) value.getObjectAt(1);
			} else {
				this.status = ReplyCheck.STATUS_DEFAULT;
			}
		}
	}

	@SuppressWarnings("unused")
	private ReplyCheck() {
		//Hiding the default constructor
	}

	/**
	 * Method getInstance.
	 * @param obj Object
	 * @return ReplyCheck
	 * @throws IOException
	 */
	public static ReplyCheck getInstance(Object obj) throws IOException {
		if (obj instanceof ReplyCheck) {
			return (ReplyCheck) obj;
		} else if (obj instanceof ASN1Sequence) {
			return new ReplyCheck(ASN1Sequence.getInstance(obj));
		} else {
			throw new IOException("Invalid ReplyCheck: " + obj.getClass());
		}
	}

	/**
	 * Method getCheck.
	 * @return ASN1ObjectIdentifier
	 */
	public ASN1ObjectIdentifier getCheck() {
		return this.check;
	}
	
	/**
	 * Method getStatus.
	 * @return ASN1Integer
	 */
	public ASN1Integer getStatus() {
		return this.status;
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

}
