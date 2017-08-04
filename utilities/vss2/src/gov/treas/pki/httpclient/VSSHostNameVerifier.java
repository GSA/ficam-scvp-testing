/**
 * 
 */
package gov.treas.pki.httpclient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * @author tejohnson
 *
 */
public class VSSHostNameVerifier implements HostnameVerifier {

	/**
	 * 
	 */
	public VSSHostNameVerifier() {

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.HostnameVerifier#verify(java.lang.String,
	 * javax.net.ssl.SSLSession)
	 */
	@Override
	public boolean verify(String arg0, SSLSession arg1) {
		/*
		 * For the moment, we trust all certificates. If used, TLS is only
		 * providing privacy, as we are fetching signed content. I.e., CRLS,
		 * OCSP responses, SCVP responses, certificates, etc.
		 */
		return true;
	}

}
