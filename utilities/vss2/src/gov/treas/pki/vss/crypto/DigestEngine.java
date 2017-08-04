/******************************************************************************
 * The following is part of the KeySupport.org PIV API
 * 
 * https://github.com/grandamp/KSJavaAPI/
 *
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 *****************************************************************************/

package gov.treas.pki.vss.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Todd E. Johnson (tejohnson@yahoo.com)
 * @version $Revision: 18 $
 */
public class DigestEngine {

	/**
	 * Method mD5Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * @return byte[]
	 */
	public static byte[] mD5Sum(byte[] ba) {
		return xSum(ba, "MD5", null);
	}

	/**
	 * Method mD5Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] mD5Sum(byte[] ba, String provider) {
		return xSum(ba, "MD5", provider);
	}

	/**
	 * Method sHA1Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA1Sum(byte[] ba) {
		return xSum(ba, "SHA-1", null);
	}

	/**
	 * Method sHA1Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA1Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-1", provider);
	}

	/**
	 * Method sHA256Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA256Sum(byte[] ba) {
		return xSum(ba, "SHA-256", null);
	}

	/**
	 * Method sHA256Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA256Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-256", provider);
	}

	/**
	 * Method sHA384Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA384Sum(byte[] ba) {
		return xSum(ba, "SHA-384", null);
	}

	/**
	 * Method sHA384Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA384Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-384", provider);
	}

	/**
	 * Method sHA512Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @return byte[]
	 */
	public static byte[] sHA512Sum(byte[] ba) {
		return xSum(ba, "SHA-512", null);
	}

	/**
	 * Method sHA512Sum.
	 * 
	 * @param ba
	 *            byte[]
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	public static byte[] sHA512Sum(byte[] ba, String provider) {
		return xSum(ba, "SHA-512", provider);
	}

	/**
	 * Method xSum.
	 * 
	 * @param ba
	 *            byte[]
	 * @param digestAlg
	 *            String
	 * 
	 * @param provider
	 *            String
	 * @return byte[]
	 */
	private static byte[] xSum(byte[] ba, String digestAlg, String provider) {
		byte[] digest = null;
		MessageDigest md = null;
		try {
			if (null == provider) {
				md = MessageDigest.getInstance(digestAlg);
			} else {
				md = MessageDigest.getInstance(digestAlg, provider);
			}
			md.update(ba);
			digest = md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return digest;
	}

	// TODO: Add methods for IO Streams as well

}
