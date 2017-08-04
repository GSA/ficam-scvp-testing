/**
 * 
 */
package gov.treas.pki.vss.scvp;

public class SCVPRequestReferenceException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructs an <code>SCVPRequestReferenceException</code> with no specified detail
	 * message.
	 */
	public SCVPRequestReferenceException() {
		super();
	}

	/**
	 * Constructs an <code>SCVPRequestReferenceException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 */
	public SCVPRequestReferenceException(String message) {
		super(message);
	}
	
	/**
	 * Constructs an <code>SCVPRequestReferenceException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 * @param cause
	 *            the exception that caused the condition
	 */
	public SCVPRequestReferenceException(String message, Throwable cause) {
		super(message, cause);
	}
}
