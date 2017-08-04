package gov.treas.pki.vss.rest.json;

import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object ocspResponseList.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class OCSPResponseList {

	/**
	 * Field ocspResponseList
	 */
	@JsonProperty("ocspResponseList")
	public List<OCSPResponse> ocspResponseList;

}
