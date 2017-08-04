package gov.treas.pki.vss.rest.json;

import javax.xml.bind.annotation.XmlRootElement;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;

/**
 * This abstract class is a Java representation of the JSON Object representing a
 * service wantBack.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class WantBack {

	/**
	 * Field certPath.
	 * 
	 * Base64 Encoded
	 */
	@JsonProperty("certPath")
	public X509CertificateList certPath;

	/**
	 * Field revocationInfo.
	 * 
	 * Base64 Encoded
	 */
	@JsonProperty("revocationInfo")
	public OCSPResponseList revocationInfo;

}
