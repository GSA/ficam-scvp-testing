package gov.treas.pki.vss.rest.json;

import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object validationFailureData.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@XmlType(propOrder = { "isAffirmativelyInvalid", "invalidityReasonList" })
@JsonIgnoreProperties(ignoreUnknown = true)
public class ValidationFailureData {

	/**
	 * Field isAffirmativelyInvalid.
	 * 
	 */
	@JsonProperty("isAffirmativelyInvalid")
	public boolean isAffirmativelyInvalid;

	/**
	 * Field invalidityReasonList.
	 * 
	 */
	@JsonProperty("invalidityReasonList")
	public List<InvalidityReason> invalidityReasonList;

}
