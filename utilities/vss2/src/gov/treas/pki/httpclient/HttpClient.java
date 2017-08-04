package gov.treas.pki.httpclient;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.pool.PoolStats;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.pkcs.ContentInfo;

import gov.treas.pki.vss.properties.VSSGlobalProperties;
import gov.treas.pki.vss.scvp.asn1.CVResponse;
import gov.treas.pki.vss.scvp.asn1.ValPolResponse;

public class HttpClient {

	private final Logger LOG = LogManager.getLogger(HttpClient.class);
	private volatile static HttpClient INSTANCE = null;
	private VSSGlobalProperties vssGP = null;
	private HttpClientContext context = null;
	private CloseableHttpClient httpClient = null;
	private PoolingHttpClientConnectionManager cm = null;
	private RequestConfig requestConfig = null;

	private enum RequestType {
		OCSP, SCVP_CV, SCVP_VP, UNKNOWN
	}

	/*
	 * RFC 5055 Mime Types
	 */
	public static final ContentType MIME_CV_REQUEST = ContentType.create("application/scvp-cv-request");
	public static final ContentType MIME_CV_RESPONSE = ContentType.create("application/scvp-cv-response");
	public static final ContentType MIME_VP_REQUEST = ContentType.create("application/scvp-vp-request");
	public static final ContentType MIME_VP_RESPONSE = ContentType.create("application/scvp-vp-response");
	/*
	 * RFC 6960 Mime Types
	 */
	public static final ContentType MIME_OCSP_REQUEST = ContentType.create("application/ocsp-request");
	public static final ContentType MIME_OCSP_RESPONSE = ContentType.create("application/ocsp-response");
	/*
	 * RFC 5280 Mime Types
	 */
	public static final ContentType MIME_CERT_RESPONSE = ContentType.create("application/pkix-cert");
	public static final ContentType MIME_CMS_RESPONSE = ContentType.create("application/pkcs7-mime");
	public static final ContentType MIME_CRL_RESPONSE = ContentType.create("application/pkix-crl");

	public static HttpClient getInstance() {
		if (INSTANCE == null) {
			synchronized (HttpClient.class) {
				if (INSTANCE == null) {
					INSTANCE = new HttpClient();
				}
			}
		}
		return INSTANCE;
	}

	public HttpClient() {

		LOG.info("Initializing Apache HTTP Client");
		vssGP = VSSGlobalProperties.getInstance();
		SSLContext sslContext = null;
		try {
			TrustManagerFactory tmf = null;
			tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(vssGP.getTrustStore());
			sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, tmf.getTrustManagers(), null);
		} catch (NoSuchAlgorithmException e) {
			LOG.error("Error creating SSLContext", e);
		} catch (KeyStoreException e) {
			LOG.error("Error creating SSLContext", e);
		} catch (KeyManagementException e) {
			LOG.error("Error creating SSLContext", e);
		}

		/*
		 * If the connection is TLS, we do not care about the server certificate
		 * path or trust, as the server certificate's issuer is in our trust
		 * store.
		 * 
		 * We are only looking for privacy of the communication.
		 */
		final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, new VSSHostNameVerifier());

		/*
		 * Initialize the Apache Pooling Connection Manager
		 */
		final Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder
				.<ConnectionSocketFactory> create().register("http", PlainConnectionSocketFactory.INSTANCE)
				.register("https", sslsf).build();

		cm = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
		cm.setMaxTotal(vssGP.getMaxConnections());
		cm.setDefaultMaxPerRoute(vssGP.getMaxConnections());
		cm.setValidateAfterInactivity(vssGP.getConnectionPoolValidationInterval());
		HttpClients.custom().setConnectionManager(cm).build();
		context = HttpClientContext.create();
		httpClient = HttpClients.custom().setConnectionManager(cm).build();

		requestConfig = RequestConfig.custom().setConnectionRequestTimeout(vssGP.getConnectionRequestTimeout())
				.setConnectTimeout(vssGP.getConnectTimeout()).setSocketTimeout(vssGP.getSocketTimeout()).build();
	}

	/**
	 * 
	 * OCSP/SCVP Client
	 * 
	 * @param url
	 * @param reqBa
	 * @param contentType
	 * @param accept
	 * @return
	 * @throws HttpClientException
	 */
	public byte[] postRequest(final URI url, byte[] reqBa, ContentType contentType, ContentType accept)
			throws HttpClientException {
		CloseableHttpResponse response = null;
		try {
			final HttpPost httppost = new HttpPost(url);
			httppost.setHeader(HttpHeaders.USER_AGENT, vssGP.getUserAgent());
			httppost.setHeader(HttpHeaders.CONTENT_TYPE, contentType.getMimeType());
			httppost.setHeader(HttpHeaders.ACCEPT, accept.getMimeType());
			HttpEntity pkixReq = new ByteArrayEntity(reqBa);
			httppost.setEntity(pkixReq);
			response = httpClient.execute(httppost, context);
			final int statusCode = response.getStatusLine().getStatusCode();
			/*
			 * Any redirects should be automatically followed. Anything other
			 * than a 200 will be considered a fail.
			 */
			if (statusCode != 200) {
				EntityUtils.consume(response.getEntity());
				response.close();
				throw new HttpClientException("Exception while requesting [" + url + "]: received HTTP Status Code: " + statusCode);
			} else {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				response.getEntity().writeTo(baos);
				EntityUtils.consume(response.getEntity());
				response.close();
				return baos.toByteArray();
			}
		} catch (final UnknownHostException e) {
			LOG.fatal("DNS or Connectivity error?:");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		} catch (final ConnectTimeoutException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getConnectTimeout() + " milliseconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		} catch (final SocketTimeoutException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getSocketTimeout() + " milliseconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		} catch (final ConnectException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getConnectionRequestTimeout() + " milliseconds: ");
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		} catch (final Exception e) {
			LOG.fatal("Common Error? Catch and re-throw explicitly!:", e);
			throw new HttpClientException("Exception while requesting [" + url + "]", e);
		} finally {
			try {
				if (response != null) {
					response.close();
				}
			} catch (final IOException e) {
				throw new HttpClientException("Exception while closing response for [" + url + "]", e);
			}
		}
	}

	@Override
	public void finalize() {
		if (cm != null) {
			LOG.info("Shutting down Apache HTTP Client PoolingHttpClientConnectionManager");
			cm.shutdown();
		}
	}

	/**
	 * This allows our status monitor to fetch the 
	 * PoolingHttpClientConnectionManager stats
	 * 
	 * @return PoolStatus
	 */
	public PoolStats getPoolStats() {
		return cm.getTotalStats();
	}

	/**
	 * 
	 * Proxy GET Request
	 * 
	 * @param uri
	 * @param request
	 * @param response
	 */
	public void processGetRequest(final URI uri, HttpServletRequest request, HttpServletResponse response) {
		CloseableHttpResponse cResponse = null;
		try {
			final HttpGet httpget = new HttpGet(uri);
			/*
			 * Set Timeouts
			 */
			httpget.setConfig(requestConfig);
			/*
			 * Set headers from the client
			 */
			Enumeration<String> headerNameEnum = request.getHeaderNames();
			while (headerNameEnum.hasMoreElements()) {
				String currentHeaderName = headerNameEnum.nextElement();
				Enumeration<String> headerValEnum = request.getHeaders(currentHeaderName);
				if (currentHeaderName.trim().equalsIgnoreCase("host")) {
					httpget.setHeader("host", uri.getHost());
				} else if (currentHeaderName.trim().equalsIgnoreCase("Content-Length")) {
					/*
					 * Do nothing, as we will reset the content length when we
					 * process the content.
					 */
				} else {
					while (headerValEnum.hasMoreElements()) {
						String currentHeaderValue = headerValEnum.nextElement();
						//LOG.info("Setting Client Header :" + currentHeaderName + ": " + currentHeaderValue);
						httpget.setHeader(currentHeaderName, currentHeaderValue);
					}
				}
			}
			//LOG.info("Executing request " + httpget.getRequestLine());
			cResponse = httpClient.execute(httpget, context);
			final int statusCode = cResponse.getStatusLine().getStatusCode();
			/*
			 * Set status code from the server
			 */
			response.setStatus(statusCode);
			/*
			 * Set headers from the server
			 */
			Header[] pResHeaders = cResponse.getAllHeaders();
			for (Header currentHeader : pResHeaders) {
				String currentHeaderName = currentHeader.getName();
				if (currentHeaderName.trim().equalsIgnoreCase("host")) {
					response.setHeader("host", uri.getHost());
				} else if (currentHeaderName.trim().equalsIgnoreCase("Content-Type")) {
					response.setContentType(currentHeader.getValue());
				}
				HeaderElement[] currentHeaderValues = currentHeader.getElements();
				for (HeaderElement currentHeaderValue : currentHeaderValues) {
					//LOG.info("Setting Server Header :" + currentHeaderName + ": " + currentHeaderValue);
					response.setHeader(currentHeaderName, currentHeaderValue.getValue());
				}
			}
			/*
			 * Set the response body from the server
			 */
			InputStream pResponseStream = cResponse.getEntity().getContent();
			BufferedInputStream bis = new BufferedInputStream(pResponseStream);
			OutputStream osResponse = response.getOutputStream();
			int resData;
			while ((resData = bis.read()) != -1) {
				osResponse.write(resData);
			}
			EntityUtils.consume(cResponse.getEntity());
			cResponse.close();
			osResponse.flush();
			osResponse.close();
		} catch (final UnknownHostException e) {
			LOG.fatal("DNS or Connectivity error?:" + e.getMessage());
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final ConnectTimeoutException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getConnectTimeout() + " milliseconds: ");
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final SocketTimeoutException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getSocketTimeout() + " milliseconds: ");
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final ConnectException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getConnectionRequestTimeout() + " milliseconds: ");
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final Exception e) {
			LOG.fatal("Common Error? Catch and re-throw explicitly!:", e);
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} finally {
			try {
				if (cResponse != null) {
					cResponse.close();
				}
			} catch (final IOException e) {
				LOG.fatal("Exception when closing response in catch block:", e);
			}
		}
	}

	/**
	 * 
	 * Proxy POST Request
	 * 
	 * @param uri
	 * @param request
	 * @param response
	 */
	public void processPostRequest(final URI uri, HttpServletRequest request, HttpServletResponse response) {
		CloseableHttpResponse cResponse = null;
		try {
			final HttpPost httpPost = new HttpPost(uri);
			/*
			 * Set Timeouts
			 */
			httpPost.setConfig(requestConfig);
			/*
			 * Set headers from the client
			 */
			Enumeration<String> headerNameEnum = request.getHeaderNames();
			while (headerNameEnum.hasMoreElements()) {
				String currentHeaderName = headerNameEnum.nextElement();
				Enumeration<String> headerValEnum = request.getHeaders(currentHeaderName);
				if (currentHeaderName.trim().equalsIgnoreCase("host")) {
					httpPost.setHeader("host", uri.getHost());
				} else if (currentHeaderName.trim().equalsIgnoreCase("Content-Length")) {
					/*
					 * Do nothing, as we will reset the content length when we
					 * process the content.
					 */
				} else {
					while (headerValEnum.hasMoreElements()) {
						String currentHeaderValue = headerValEnum.nextElement();
						//LOG.info("Setting Client Header :" + currentHeaderName + ": " + currentHeaderValue);
						httpPost.setHeader(currentHeaderName, currentHeaderValue);
					}
				}
			}
			InputStream is = request.getInputStream();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buf = new byte[1000];
			for (int nChunk = is.read(buf); nChunk != -1; nChunk = is.read(buf)) {
				baos.write(buf, 0, nChunk);
			}
			byte[] postEntityBytes = baos.toByteArray();
			/*
			 * We will inspect the request to make sure it is one of:
			 * 
			 * -OCSP Request -SCVP Validation Request -SCVP Policy Request
			 * 
			 * All other data will yield HTTP error code
			 * 
			 * TODO: Add inspection of the request, and logging, before we are
			 * even called.
			 */
			if (null == postEntityBytes || postEntityBytes.length < 3) {
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			} else if (postEntityBytes[0] != (byte) 0x30) {
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			}
			RequestType reqType = RequestType.UNKNOWN;
			/*
			 * First we will check if the request is OCSP
			 */
			try {
				@SuppressWarnings("unused")
				OCSPRequest eReq = OCSPRequest.getInstance(postEntityBytes);
				reqType = RequestType.OCSP;
			} catch (IllegalArgumentException e) {
			}
			/*
			 * Next, we will check to see if the request is SCVP
			 */
			if (reqType == RequestType.UNKNOWN) {
				try {
					ContentInfo eReq = ContentInfo.getInstance(postEntityBytes);
					/*
					 * This could be a signed request, if so, then we need to
					 * get the content, and check *its* ContentInfo.
					 */
					ASN1ObjectIdentifier eReqOid = eReq.getContentType();

					if (eReqOid.equals(CMSObjectIdentifiers.signedData)) {

					} else if (eReqOid.equals(CMSObjectIdentifiers.authenticatedData)) {

					}
					if (eReqOid.equals(CVResponse.idCtScvpCertValResponse)) {
						reqType = RequestType.SCVP_CV;
					} else if (eReqOid.equals(ValPolResponse.idCtScvpvalPolResponse)) {
						reqType = RequestType.SCVP_VP;
					} else {
						reqType = RequestType.UNKNOWN;
					}
				} catch (IllegalArgumentException e) {
				}
			}
			/*
			 * Now we will process, setting the correct request mime type,
			 * regardless of what the client sent.
			 */
			ContentType reqContentType = null;
			switch (reqType) {
			case UNKNOWN:
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			case OCSP:
				reqContentType = HttpClient.MIME_OCSP_REQUEST;
				break;
			case SCVP_CV:
				reqContentType = HttpClient.MIME_CV_REQUEST;
				break;
			case SCVP_VP:
				reqContentType = HttpClient.MIME_VP_REQUEST;
				break;
			default:
				response.sendError(HttpServletResponse.SC_BAD_REQUEST);
				return;
			}
			HttpEntity postEntity = EntityBuilder.create().setBinary(postEntityBytes).setContentType(reqContentType)
					.build();
			httpPost.setEntity(postEntity);
			/*
			 * Execute the request
			 */
			//LOG.info("Executing request " + httpPost.getRequestLine());
			cResponse = httpClient.execute(httpPost, context);
			final int statusCode = cResponse.getStatusLine().getStatusCode();
			/*
			 * Set status code from the server
			 */
			response.setStatus(statusCode);
			/*
			 * Set headers from the server
			 */
			Header[] pResHeaders = cResponse.getAllHeaders();
			for (Header currentHeader : pResHeaders) {
				String currentHeaderName = currentHeader.getName();
				if (currentHeaderName.trim().equalsIgnoreCase("host")) {
					response.setHeader("host", uri.getHost());
				} else if (currentHeaderName.trim().equalsIgnoreCase("Content-Type")) {
					response.setContentType(currentHeader.getValue());
				}
				HeaderElement[] currentHeaderValues = currentHeader.getElements();
				for (HeaderElement currentHeaderValue : currentHeaderValues) {
					//LOG.info("Setting Server Header :" + currentHeaderName + ": " + currentHeaderValue);
					response.setHeader(currentHeaderName, currentHeaderValue.getValue());
				}
			}
			/*
			 * Set the response body from the server
			 */
			InputStream pResponseStream = cResponse.getEntity().getContent();
			BufferedInputStream bis = new BufferedInputStream(pResponseStream);
			OutputStream osResponse = response.getOutputStream();
			int resData;
			while ((resData = bis.read()) != -1) {
				osResponse.write(resData);
			}
			EntityUtils.consume(cResponse.getEntity());
			cResponse.close();
			osResponse.flush();
			osResponse.close();
		} catch (final UnknownHostException e) {
			LOG.fatal("DNS or Connectivity error?:" + e.getMessage());
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final ConnectTimeoutException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getConnectTimeout() + " milliseconds: ");
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final SocketTimeoutException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getSocketTimeout() + " milliseconds: ");
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final ConnectException e) {
			LOG.fatal("Timeout Reached: Current Timeout: " + vssGP.getConnectionRequestTimeout() + " milliseconds: ");
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} catch (final Exception e) {
			LOG.fatal("Common Error? Catch and re-throw explicitly!:", e);
			try {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			} catch (IOException e1) {
				LOG.fatal("Exception sending Error 500: " + e1.getMessage());
			}
		} finally {
			try {
				if (cResponse != null) {
					cResponse.close();
				}
			} catch (final IOException e) {
				LOG.fatal("Exception when closing response in catch block:", e);
			}
		}
	}

}
