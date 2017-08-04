package gov.treas.pki.vss.rest.json;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object invalidityReason.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@XmlType(propOrder = { "invalidityReasonToken", "invalidityReasonText" })
@JsonIgnoreProperties(ignoreUnknown = true)
public class InvalidityReason {

	/**
	 * Field invalidityReasonToken.
	 * 
	 */
	@JsonProperty("invalidityReasonToken")
	public String invalidityReasonToken;

	/**
	 * Field invalidityReasonText.
	 * 
	 */
	@JsonProperty("invalidityReasonText")
	public String invalidityReasonText;

}
