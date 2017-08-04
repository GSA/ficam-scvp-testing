package gov.treas.pki.vss.pkix;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import gov.treas.pki.httpclient.HttpClient;
import gov.treas.pki.vss.properties.VSSGlobalProperties;

public class PkixServiceEndpoints extends HttpServlet {

	/**
	 * Serialization UID.
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Field LOG.
	 */
	private final Logger LOG = LogManager.getLogger(PkixServiceEndpoints.class);

	/**
	 * Field vssGP
	 */
	private VSSGlobalProperties vssGP = null;

	/**
	 * Field SCVPSERVICE
	 */
	private URI scvpServiceUri = null;

	private HttpClient proxy = null;

	/**
	 * Field basePath
	 */
	private static String basePath = "/vss/pkix";

	/**
	 * Initialize the <code>ProxyServlet</code>
	 * 
	 * @param servletConfig
	 *            The Servlet configuration passed in by the servlet conatiner
	 */
	public void init(ServletConfig servletConfig) {
		/*
		 * Get the properties
		 */
		vssGP = VSSGlobalProperties.getInstance();
		scvpServiceUri = vssGP.getScvpServerURI();
		/*
		 * Get HTTP Client Instance
		 */
		proxy = HttpClient.getInstance();
		/*
		 * We will be passing base64 encoded OCSP GET requests, so the following
		 * is needed.
		 * 
		 * TODO:  Setting the system property does not appear to work from within the servlet.
		 * 
		 * It would appear it must be set via an environment variable for the JRE:
		 * 
		 * `export CATALINA_OPTS="$CATALINA_OPTS -Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=true"`
		 */
		System.setProperty("org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH", "true");
		/*
		 * Debug logging for Apache HTTP Client
		 */
/*		System.setProperty("org.apache.commons.logging.Log","org.apache.commons.logging.impl.SimpleLog");
		System.setProperty("org.apache.commons.logging.simplelog.showdatetime", "true");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.wire", "DEBUG");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.impl.conn", "DEBUG");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.impl.client", "DEBUG");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http.client", "DEBUG");
		System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", "DEBUG");
*/	
	}

	/**
	 * Performs an HTTP GET request
	 * 
	 * @param request
	 *            The {@link HttpServletRequest} object passed in by the servlet
	 *            engine representing the client request to be proxied
	 * @param response
	 *            The {@link HttpServletResponse} object by which we can send a
	 *            proxied response to the client
	 */
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		proxy.processGetRequest(getProxyiedURI(request, response), request, response);
	}

	/**
	 * Performs an HTTP POST request
	 * 
	 * @param request
	 *            The {@link HttpServletRequest} object passed in by the servlet
	 *            engine representing the client request to be proxied
	 * @param response
	 *            The {@link HttpServletResponse} object by which we can send a
	 *            proxied response to the client
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		proxy.processPostRequest(getProxyiedURI(request, response), request, response);
	}

	public String getServletInfo() {
		return "PKIX Endpoint Proxy";
	}

	public static String getFullURL(HttpServletRequest request) {
		StringBuffer requestURL = request.getRequestURL();
		String queryString = request.getQueryString();
		if (queryString == null) {
			return requestURL.toString();
		} else {
			return requestURL.append('?').append(queryString).toString();
		}
	}

	public URI getProxyiedURI(HttpServletRequest request, HttpServletResponse response) {
		URI uri = null;
		try {
			URI requestUri = new URI(getFullURL(request));
			int baseIndex = requestUri.toString().indexOf(basePath) + basePath.length();
			String relativeUri = requestUri.toString().substring(baseIndex);
			uri = new URI(scvpServiceUri + relativeUri);
			//LOG.info("Proxied Request URI:" + uri.toString());
		} catch (URISyntaxException e) {
			LOG.fatal("Error with proxied URI: " + e);
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		}
		return uri;
	}

}