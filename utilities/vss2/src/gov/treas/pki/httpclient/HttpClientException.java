package gov.treas.pki.httpclient;

public class HttpClientException extends Exception {


	/**
	 * 
	 */
	private static final long serialVersionUID = -3319405741656490397L;

	public HttpClientException() {
		super();
	}

	public HttpClientException(String message) {
		super(message);
	}

	public HttpClientException(Throwable cause) {
		super(cause);
	}

	public HttpClientException(String message, Throwable cause) {
		super(message, cause);
	}

}
