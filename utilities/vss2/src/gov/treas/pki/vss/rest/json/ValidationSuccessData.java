package gov.treas.pki.vss.rest.json;

import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object validationSuccessData.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class ValidationSuccessData {

	/**
	 * Field wantBackResultList.
	 * 
	 */
	@JsonProperty("wantBackResultList")
	public List<WantBack> wantBackResultList;

}
