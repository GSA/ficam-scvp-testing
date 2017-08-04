package gov.treas.pki.vss.x509;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;

import gov.treas.pki.vss.rest.json.SANValue;

/**
 * This is intended to be a class with static methods to 
 * perform some basing X509 parsing.
 */
public class X509Util {

	private static final String numbers = "0123456789ABCDEF";

	/**
	 * 
	 */
	private X509Util() {
		/*
		 *  Hidden constructor
		 */
	}

	/**
	 * Method getSubjectAlternativeNames.
	 * 
	 * @param certificate
	 *            X509Certificate
	 * @return Map<String,String>
	 * @throws IOException
	 */
	public static List<SANValue> getSubjectAlternativeNames(
			X509Certificate certificate) throws IOException {

		byte[] encodedExtension;
		List<SANValue> x509SubjectAltName = null;
		DEROctetString content;
		ASN1Sequence sequence;
		Integer tag;
		GeneralName generalName;

		/*
		 * We are pulling the DER encoded value of subjectAltName and we are
		 * going to parse each SAN value manually
		 */
		encodedExtension = certificate.getExtensionValue("2.5.29.17");
		x509SubjectAltName = new ArrayList<SANValue>();
		if (null == encodedExtension) {
			return x509SubjectAltName;
		}
		content = (DEROctetString) DEROctetString
				.fromByteArray(encodedExtension);
		sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(content
				.getOctets());
		Enumeration<?> it = sequence.getObjects();
		while (it.hasMoreElements()) {
			generalName = GeneralName.getInstance(it.nextElement());
			tag = generalName.getTagNo();
			switch (tag) {
			case GeneralName.otherName: {
				/*
				 * otherName requires the encoding of the value be defined by
				 * the type-id, which is an ObjectIdentifier
				 */
				ASN1Sequence otherName = (ASN1Sequence) generalName.getName();
				ASN1ObjectIdentifier typeId = (ASN1ObjectIdentifier) otherName
						.getObjectAt(0);
				ASN1TaggedObject value = (ASN1TaggedObject) otherName
						.getObjectAt(1);
				/*
				 * pivFASC-N (2.16.840.1.101.3.6.6)
				 */
				if (typeId.equals(new ASN1ObjectIdentifier(
						"2.16.840.1.101.3.6.6"))) {
					/*
					 * Remove prepended "#", if it exists. Assuming it is
					 * injected by Java code somewhere, because that character
					 * is not part of the literal encoding.
					 */
					String rawFascnValue = value.getObject().toString()
							.toUpperCase();
					if (rawFascnValue.startsWith("#")) {
						rawFascnValue = rawFascnValue.substring(1);
					}
					SANValue fascn = new SANValue();
					fascn.type = "otherName:pivFASC-N";
					fascn.value = rawFascnValue;
					x509SubjectAltName.add(fascn);
					/*
					 * userPrincipalName (1.3.6.1.4.1.311.20.2.3)
					 */
				} else if (typeId.equals(new ASN1ObjectIdentifier(
						"1.3.6.1.4.1.311.20.2.3"))) {
					SANValue upn = new SANValue();
					upn.type = "otherName:userPrincipalName";
					upn.value = value.getObject().toString();
					x509SubjectAltName.add(upn);
				} else {
					SANValue ukOther = new SANValue();
					ukOther.type = "otherName";
					ukOther.value = generalName.getName().toString();
					x509SubjectAltName.add(ukOther);
				}
				break;
			}
			case GeneralName.rfc822Name: {
				SANValue rfc822Name = new SANValue();
				rfc822Name.type = "rfc822Name";
				rfc822Name.value = generalName.getName().toString();
				x509SubjectAltName.add(rfc822Name);
				break;
			}
			case GeneralName.dNSName: {
				SANValue dNSName = new SANValue();
				dNSName.type = "dNSName";
				dNSName.value = generalName.getName().toString();
				x509SubjectAltName.add(dNSName);
				break;
			}
			case GeneralName.x400Address: {
				SANValue x400Address = new SANValue();
				x400Address.type = "x400Address";
				x400Address.value = generalName.getName().toString();
				x509SubjectAltName.add(x400Address);
				break;
			}
			case GeneralName.directoryName: {
				SANValue directoryName = new SANValue();
				directoryName.type = "directoryName";
				directoryName.value = generalName.getName().toString();
				x509SubjectAltName.add(directoryName);
				break;
			}
			case GeneralName.ediPartyName: {
				SANValue ediPartyName = new SANValue();
				ediPartyName.type = "ediPartyName";
				ediPartyName.value = generalName.getName().toString();
				x509SubjectAltName.add(ediPartyName);
				break;
			}
			case GeneralName.uniformResourceIdentifier: {
				SANValue uniformResourceIdentifier = new SANValue();
				uniformResourceIdentifier.type = "uniformResourceIdentifier";
				uniformResourceIdentifier.value = generalName.getName().toString();
				x509SubjectAltName.add(uniformResourceIdentifier);
				break;
			}
			case GeneralName.iPAddress: {
				SANValue iPAddress = new SANValue();
				iPAddress.type = "iPAddress";
				iPAddress.value = generalName.getName().toString();
				x509SubjectAltName.add(iPAddress);
				break;
			}
			case GeneralName.registeredID: {
				SANValue registeredID = new SANValue();
				registeredID.type = "iPAddress";
				registeredID.value = generalName.getName().toString();
				x509SubjectAltName.add(registeredID);
				break;
			}
			default: {
				// No real possible way to get here
				SANValue unknown = new SANValue();
				unknown.type = "unknown";
				unknown.value = generalName.getName().toString();
				x509SubjectAltName.add(unknown);
				break;
			}
			}
		}
		return x509SubjectAltName;
	}

	/**
	 * Return Hex String of SHA-256 digest of the certificate
	 * 
	 * @param cert
	 * @return
	 */
	public static String getVssCertId(X509Certificate cert) {
		byte[] digest = null;
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
			md.update(cert.getEncoded());
			digest = md.digest();
		} catch (NoSuchAlgorithmException | CertificateEncodingException e) {
			e.printStackTrace();
		}
		
		return byteArrayToString(digest);
	}
	
	/**
	 * Convert a byte array to a Hex String
	 * 
	 * The following method converts a byte[] object to a String object, where
	 * the only output characters are "0123456789ABCDEF".
	 * 
	 * @param ba
	 *            A byte array
	
	 * @return String Hexidecimal String object which represents the contents of
	 *         the byte array */
	public static String byteArrayToString(byte[] ba) {
		if (ba == null) {
			return "";
		}
		StringBuffer hex = new StringBuffer(ba.length * 2);
		for (int i = 0; i < ba.length; i++) {
			hex.append(Integer.toString((ba[i] & 0xff) + 0x100, 16)
					.substring(1));
		}
		return hex.toString().toUpperCase(Locale.US);
	}

	/**
	 * Convert a Hex String to a byte array
	 * 
	 * The following method converts a String object to a byte[] object, where
	 * the only valid input characters is "0123456789ABCDEF".
	 * 
	 * @param s
	 *            Hexidecimal String object to convert to a byte array
	
	 * @return byte[] A byte array */
	public static byte[] stringToByteArray(String s) {
		if (s == null)
			return null;
		byte[] result = new byte[s.length() / 2];
		for (int i = 0; i < s.length(); i += 2) {
			int i1 = numbers.indexOf(s.charAt(i));
			int i2 = numbers.indexOf(s.charAt(i + 1));
			result[i / 2] = (byte) ((i1 << 4) | i2);
		}
		return result;
	}

	/**
	 * XOR two byte arrays
	 * 
	 * The following method is used to XOR two byte array objects
	 * 
	 * @param array1
	 *            A byte array
	 * @param array2
	 *            A byte array
	
	 * @return byte[] The result of array1^array2 */
	public static byte[] XOR(byte[] array1, byte[] array2) {
		byte[] result = new byte[array1.length];
		for (int i = 0; i < array1.length; i++) {
			result[i] = (byte) (array1[i] ^ array2[i]);
		}
		return result;
	}

}
