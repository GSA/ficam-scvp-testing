package gov.treas.pki.vss.status.json;


import javax.xml.bind.annotation.XmlRootElement;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class ConnectionPoolStats {

	/**
	 * Field available
	 */
	@JsonProperty("available")
	public int available;

	/**
	 * Field leased
	 */
	@JsonProperty("leased")
	public int leased;

	/**
	 * Field max
	 */
	@JsonProperty("max")
	public int max;

	/**
	 * Field pending
	 */
	@JsonProperty("pending")
	public int pending;

}
