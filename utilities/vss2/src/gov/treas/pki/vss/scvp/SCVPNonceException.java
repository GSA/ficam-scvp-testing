/**
 * 
 */
package gov.treas.pki.vss.scvp;

public class SCVPNonceException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructs an <code>SCVPNonceException</code> with no specified detail
	 * message.
	 */
	public SCVPNonceException() {
		super();
	}

	/**
	 * Constructs an <code>SCVPNonceException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 */
	public SCVPNonceException(String message) {
		super(message);
	}
	
	/**
	 * Constructs an <code>SCVPNonceException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 * @param cause
	 *            the exception that caused the condition
	 */
	public SCVPNonceException(String message, Throwable cause) {
		super(message, cause);
	}
}
