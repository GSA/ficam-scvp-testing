package gov.treas.pki.vss.rest.json;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object transactionResult.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@XmlType(propOrder = { "transactionResultToken", "transactionResultText" })
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransactionResult {

	/**
	 * Field transactionResultToken.
	 * 
	 */
	@JsonProperty("transactionResultToken")
	public String transactionResultToken;

	/**
	 * Field transactionResultText.
	 * 
	 */
	@JsonProperty("transactionResultText")
	public String transactionResultText;

}
