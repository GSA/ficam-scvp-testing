package gov.treas.pki.vss.scvp;

public class SCVPException extends Throwable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Constructs an <code>SCVPException</code> with no specified detail
	 * message.
	 */
	public SCVPException() {
		super();
	}

	/**
	 * Constructs an <code>SCVPException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 */
	public SCVPException(String message) {
		super(message);
	}
	
	/**
	 * Constructs an <code>SCVPException</code> with the specified detail
	 * message.
	 * 
	 * @param message
	 *            the detail message.
	 * @param cause
	 *            the exception that caused the condition
	 */
	public SCVPException(String message, Throwable cause) {
		super(message, cause);
	}
}
