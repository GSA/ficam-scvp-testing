package gov.treas.pki.vss.rest.json;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object SANValue.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@XmlType(propOrder = { "type", "value" })
@JsonIgnoreProperties(ignoreUnknown = true)
public class SANValue {

	/**
	 * Field type.
	 * 
	 * This is the General Name type.
	 */
	@JsonProperty("type")
	public String type;

	/**
	 * Field value.
	 * 
	 * This is the General Name value.
	 */
	@JsonProperty("value")
	public String value;

}
