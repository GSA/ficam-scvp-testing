package gov.treas.pki.vss.rest.json;

import java.util.List;

import javax.xml.bind.annotation.XmlRootElement;

import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 * This class is a Java representation of the JSON Object x509CertificateList.
 * 
 * @author tejohnson
 * 
 * @version $Revision: 1.0 $
 */
@XmlRootElement
@JsonIgnoreProperties(ignoreUnknown = true)
public class X509CertificateList {

	/**
	 * Field x509CertificateList
	 */
	@JsonProperty("x509CertificateList")
	public List<X509Certificate> x509CertificateList;

}
