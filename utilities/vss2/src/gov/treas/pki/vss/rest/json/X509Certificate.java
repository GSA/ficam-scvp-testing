package gov.treas.pki.vss.rest.json;

import javax.xml.bind.annotation.XmlRootElement;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object x509Certificate.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class X509Certificate {

	/**
	 * Field x509Certificate
	 */
	@JsonProperty("x509Certificate")
	public String x509Certificate;

}
