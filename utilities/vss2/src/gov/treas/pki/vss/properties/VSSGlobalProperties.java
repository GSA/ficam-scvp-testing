package gov.treas.pki.vss.properties;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.InvalidPropertiesFormatException;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This class is a singleton that is initialized when the web application is
 * started. To ensure this object is updated in memory from the properties file,
 * the web application MUST be stopped and started / reloaded.
 */
public class VSSGlobalProperties {

	/**
	 * Field LOG.
	 */
	private final Logger LOG = LogManager.getLogger(VSSGlobalProperties.class);

	/**
	 * Field INSTANCE.
	 */
	private volatile static VSSGlobalProperties INSTANCE;
	
	/**
	 * Field scvpSignerIssuer.
	 */
	private X509Certificate scvpSignerIssuer = null;

	/**
	 * Field scvpServerURI.
	 */
	private URI scvpServerURI = null;

	/**
	 * Field requestorNameUri. (default value is "URN:VSSAPI:HOSTNAME")
	 */
	private String requestorNameUri = "URN:VSSAPI:HOSTNAME";

	/**
	 * Field trustStore
	 */
	private KeyStore trustStore = null;

	/**
	 * Field connectTimeout. (default value is 30 sec)
	 */
	private int connectTimeout = 30000;

	/**
	 * Field connectionRequestTimeout. (default value is 30 sec)
	 */
	private int connectionRequestTimeout = 30000;

	/**
	 * Field socketTimeout. (default value is 30 sec)
	 */
	private int socketTimeout = 30000;

	/**
	 * Field maxConnections. (default value is 800)
	 */
	private int maxConnections = 800;

	/**
	 * Field userAgent. (default value is "VSS Rest Service Client")
	 */
	private String userAgent = "VSS Rest Service Client";

	/**
	 * Field connectionPoolValidationInterval. (default value is 5 sec)
	 */
	private int connectionPoolValidationInterval = 5000;

	private boolean derEncodeDefaults = false;
	private boolean functioningAsTestClient = false;

	/**
	 * Protected constructor for our Singleton.
	 */
	protected VSSGlobalProperties() {

		InputStream is = null;
		char[] trustStorePass = null;
		String trustStoreIssuerLabel = null;
		Properties props = getProperties();

		if (null == props) {
			throw new RuntimeException("Could not load properties!");
		}
		String trustStoreFile = props.getProperty("VSS_TRUSTSTORE_FILE");
		try {
			is = new FileInputStream(trustStoreFile);
		} catch (FileNotFoundException e) {
			LOG.error("Failed to load trust store file defined in vss.properties", e);
		}
		trustStorePass = props.getProperty("VSS_TRUSTSTORE_PASS").toCharArray();
		trustStoreIssuerLabel = props.getProperty("VSS_TRUSTSTORE_SCVP_SIGNER_ISSUER_LABEL");
		try {
			scvpServerURI = new URI(props.getProperty("VSS_SCVP_SERVER_URI"));
			LOG.info("SCVP Server URI is: " + scvpServerURI);
		} catch (URISyntaxException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_SERVER_URI", e);
		}
		requestorNameUri = props.getProperty("VSS_SCVP_REQUESTOR_NAME_URI");
		userAgent = props.getProperty("VSS_SCVP_CLIENT_USER_AGENT");
		try {
			connectTimeout = new Integer(props.getProperty("VSS_SCVP_CONNECT_TIMEOUT")).intValue();
		} catch (NumberFormatException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_CONNECT_TIMEOUT", e);
		}
		try {
			connectionRequestTimeout = new Integer(props.getProperty("VSS_SCVP_CONNECTIONREQUEST_TIMEOUT")).intValue();
		} catch (NumberFormatException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_CONNECTIONREQUEST_TIMEOUT", e);
		}
		try {
			socketTimeout  = new Integer(props.getProperty("VSS_SCVP_SOCKET_TIMEOUT")).intValue();
		} catch (NumberFormatException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_SOCKET_TIMEOUT", e);
		}
		try {
			maxConnections = new Integer(props.getProperty("VSS_SCVP_MAX_CONNECTIONS")).intValue();
		} catch (NumberFormatException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_MAX_CONNECTIONS", e);
		}
		try {
			connectionPoolValidationInterval = new Integer(props.getProperty("VSS_SCVP_CONNECTION_POOL_VALIDATION_INTERVAL")).intValue();
		} catch (NumberFormatException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_CONNECT_TIMEOUT", e);
		}
		try {
			derEncodeDefaults = Boolean.valueOf(props.getProperty("VSS_SCVP_DER_ENCODE_DEFAULTS")).booleanValue();
		} catch (NumberFormatException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_DER_ENCODE_DEFAULTS", e);
		}
		try {
			functioningAsTestClient = Boolean.valueOf(props.getProperty("VSS_SCVP_TEST_CLIENT")).booleanValue();
		} catch (NumberFormatException e) {
			LOG.error("Failed to parse vss.properties: VSS_SCVP_TEST_CLIENT", e);
		}
		try {
			trustStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			LOG.error("Failed to get Java JKS Keystore INSTANCE", e);
		}
		if (null != trustStore) {
			try {
				trustStore.load(is, trustStorePass);
			} catch (NoSuchAlgorithmException e) {
				LOG.error("Failed to load Java JKS Keystore", e);
			} catch (CertificateException e) {
				LOG.error("Failed to load Java JKS Keystore", e);
			} catch (IOException e) {
				LOG.error("Failed to load Java JKS Keystore", e);
			}
			try {
				scvpSignerIssuer = (X509Certificate) trustStore.getCertificate(trustStoreIssuerLabel);
			} catch (KeyStoreException e) {
				LOG.error("Failed to load certificate from keystore with label: " + trustStoreIssuerLabel, e);
			}
		} else {
			LOG.fatal("Failed to trust store!  SCVP response signature validation will fail!");
		}
	}

	/**
	 * 
	 * 
	 * @return CommonPolicyRootCA
	 * @throws CertificateException
	 */
	public static VSSGlobalProperties getInstance() {
		if (INSTANCE == null) {
			synchronized (VSSGlobalProperties.class) {
				if (INSTANCE == null) {
					INSTANCE = new VSSGlobalProperties();
				}
			}
		}
		return INSTANCE;
	}

	/**
	 * Method getProperties.
	 * 
	 * Returns the properties stored in "c", or the "vss.properties" from the
	 * deployed .war file if the other file can not be read.
	 * 
	 * @return Properties
	 */
	private Properties getProperties() {
		InputStream is = null;
		Properties props = null;

		try {
			is = new FileInputStream(System.getProperty("vss.configLocation", "/usr/local/tomcat/conf/vss.properties"));
			try {
				props = new Properties();
				props.load(is);
				is.close();
			} catch (InvalidPropertiesFormatException e) {
				props = null;
				LOG.error("Error loading properties due to bad formatting", e);
			} catch (IOException e) {
				props = null;
				LOG.error("Error loading properties", e);
			}
		} catch (FileNotFoundException e) {
			LOG.error("Error loading properties from: " + System.getProperty("vss.configLocation", "/usr/local/tomcat/conf/vss.properties"), e);
		}
		return props;
	}

	/**
	 * @return the trustStore
	 */
	public KeyStore getTrustStore() {
		return trustStore;
	}

	/**
	 * Method getSCVPSignerIsserCertificate.
	 * 
	 * @return X509Certificate
	 */
	public X509Certificate getSCVPSignerIsser() {
		return scvpSignerIssuer;
	}

	/**
	 * @param scvpSignerIssuer
	 *            the scvpSignerIssuer to set
	 */
	public void setScvpSignerIssuer(X509Certificate scvpSignerIssuer) {
		this.scvpSignerIssuer = scvpSignerIssuer;
	}

	/**
	 * @return the scvpServerURI
	 */
	public URI getScvpServerURI() {
		return scvpServerURI;
	}

	/**
	 * @return the requestorNameUri
	 */
	public String getRequestorNameUri() {
		return requestorNameUri;
	}

	/**
	 * @return the connectTimeout
	 */
	public int getConnectTimeout() {
		return connectTimeout;
	}

	/**
	 * @return the connectionRequestTimeout
	 */
	public int getConnectionRequestTimeout() {
		return connectionRequestTimeout;
	}

	/**
	 * @return the socketTimeout
	 */
	public int getSocketTimeout() {
		return socketTimeout;
	}

	/**
	 * @return the maxConnections
	 */
	public int getMaxConnections() {
		return maxConnections;
	}

	/**
	 * @return the userAgent
	 */
	public String getUserAgent() {
		return userAgent;
	}

	/**
	 * @return the connectionPoolValidationInterval
	 */
	public int getConnectionPoolValidationInterval() {
		return connectionPoolValidationInterval;
	}

	public boolean getDerEncodeDefaults() {
		return derEncodeDefaults;
	}

	public boolean isFunctioningAsTestClient() {
		return functioningAsTestClient;
	}
}
