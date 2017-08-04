package gov.treas.pki.vss.rest.json;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON response.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@XmlType(propOrder = { "transactionResult", "validationResult" })
@JsonIgnoreProperties(ignoreUnknown = true)
public class VSSResponse {

	/**
	 * Field transactionResult.
	 */
	@JsonProperty("transactionResult")
	public TransactionResult transactionResult;

	/**
	 * Field validationResult.
	 */
	@JsonProperty("validationResult")
	public ValidationResult validationResult;

}
