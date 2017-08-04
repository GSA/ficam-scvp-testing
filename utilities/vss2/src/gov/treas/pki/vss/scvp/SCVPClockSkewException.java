/**
 * 
 */
package gov.treas.pki.vss.scvp;

public class SCVPClockSkewException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructs an <code>SCVPClockSkewException</code> with no specified detail
	 * message.
	 */
	public SCVPClockSkewException() {
		super();
	}

	/**
	 * Constructs an <code>SCVPClockSkewException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 */
	public SCVPClockSkewException(String message) {
		super(message);
	}
	
	/**
	 * Constructs an <code>SCVPClockSkewException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 * @param cause
	 *            the exception that caused the condition
	 */
	public SCVPClockSkewException(String message, Throwable cause) {
		super(message, cause);
	}
}
