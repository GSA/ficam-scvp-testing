package gov.treas.pki.vss.status.json;

import javax.xml.bind.annotation.XmlRootElement;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class Stats {

	/**
	 * Field ConnectionPoolStats
	 */
	@JsonProperty("ConnectionPoolStats")
	public ConnectionPoolStats connectionPoolStats;

}
