package gov.treas.pki.vss.rest.json;

import java.io.IOException;
import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.annotate.JsonCreator;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

/**
 * This class is a Java representation of the JSON request.
 * 
 * @version $Revision: 1.3 $
 */
@XmlRootElement
@XmlType(propOrder = { "validationPolicy", "wantBackList", "x509CertificateList" })
@JsonIgnoreProperties(ignoreUnknown = true)
public class VSSRequest {

	/**
	 * Static creator for de-serialization
	 * 
	 * @throws IOException 
	 * @throws JsonMappingException 
	 * @throws JsonParseException 
	 */
	@JsonCreator
	public static VSSRequest getInstance(String jsonString) throws JsonParseException, JsonMappingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		VSSRequest req = null;
		req = mapper.readValue(jsonString, VSSRequest.class);
		return req;
	}

	/**
	 * Default Constructor
	 * 
	 * @param validationPolicy
	 * @param wantBackList
	 * @param x509CertificateList
	 */
	@JsonCreator
	public VSSRequest(@JsonProperty("validationPolicy") String validationPolicy,
			@JsonProperty("wantBackList") List<WantBackTypeToken> wantBackList,
			@JsonProperty("x509CertificateList") List<X509Certificate> x509CertificateList) {
		this.validationPolicy = validationPolicy;
		this.wantBackList = wantBackList;
		this.x509CertificateList = x509CertificateList;
	}

	/**
	 * Field validationPolicy.
	 */
	@JsonProperty("validationPolicy")
	public String validationPolicy;

	/**
	 * Field wantBackList.
	 */
	@JsonProperty("wantBackList")
	public List<WantBackTypeToken> wantBackList;

	/**
	 * Field x509CertificateList
	 */
	@JsonProperty("x509CertificateList")
	public List<X509Certificate> x509CertificateList;

}
