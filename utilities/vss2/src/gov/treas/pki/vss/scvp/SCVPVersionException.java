/**
 * 
 */
package gov.treas.pki.vss.scvp;

public class SCVPVersionException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructs an <code>SCVPVersionException</code> with no specified detail
	 * message.
	 */
	public SCVPVersionException() {
		super();
	}

	/**
	 * Constructs an <code>SCVPVersionException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 */
	public SCVPVersionException(String message) {
		super(message);
	}
	
	/**
	 * Constructs an <code>SCVPVersionException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 * @param cause
	 *            the exception that caused the condition
	 */
	public SCVPVersionException(String message, Throwable cause) {
		super(message, cause);
	}
}
