package gov.treas.pki.vss.rest.json;

import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;

/**
 * This class is a Java representation of the JSON object ResultByCertificate's Data.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@XmlType(propOrder = { "vssCertId", "x509SubjectName", "x509IssuerName", "x509SerialNumber", "x509SubjectAltName", "validationTime", "nextUpdate", "validationResultToken", "validationFailureData", "validationSuccessData" })
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonSerialize(include = JsonSerialize.Inclusion.NON_NULL)
public class ResultByCertificateData {

	/**
	 * Field validationResultToken.
	 * 
	 */
	@JsonProperty("validationResultToken")
	public String validationResultToken;

	/**
	 * Field validationFailureData.
	 * 
	 */
	@JsonProperty("validationFailureData")
	public ValidationFailureData validationFailureData;

	/**
	 * Field validationSuccessData.
	 * 
	 */
	@JsonProperty("validationSuccessData")
	public ValidationSuccessData validationSuccessData;

	/**
	 * Field X509IssuerName.
	 */
	@JsonProperty("x509IssuerName")
	public String x509IssuerName;

	/**
	 * Field vssCertId.
	 */
	@JsonProperty("vssCertId")
	public String vssCertId;

	/**
	 * Field X509SerialNumber.
	 */
	@JsonProperty("x509SerialNumber")
	public String x509SerialNumber;

	/*
	 * Field x509SubjectAltName
	 */
	@JsonProperty("x509SubjectAltName")
	public List<SANValue> x509SubjectAltName;

	/**
	 * Field X509SubjectName.
	 */
	@JsonProperty("x509SubjectName")
	public String x509SubjectName;

	/**
	 * Field validationTime.
	 * 
	 * Base64 Encoded
	 */
	@JsonProperty("validationTime")
	public String validationTime;

	/**
	 * Field nextUpdate.
	 * 
	 * Base64 Encoded
	 */
	@JsonProperty("nextUpdate")
	public String nextUpdate;

}
