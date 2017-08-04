package gov.treas.pki.vss.rest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.pool.PoolStats;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

import gov.treas.pki.httpclient.HttpClient;
import gov.treas.pki.vss.rest.json.ResultByCertificate;
import gov.treas.pki.vss.rest.json.TransactionResult;
import gov.treas.pki.vss.rest.json.VSSRequest;
import gov.treas.pki.vss.rest.json.VSSResponse;
//import gov.treas.pki.vss.rest.json.ValidationResponse;
import gov.treas.pki.vss.rest.json.ValidationResult;
import gov.treas.pki.vss.rest.json.WantBackTypeToken;
import gov.treas.pki.vss.scvp.SCVPClient;
import gov.treas.pki.vss.scvp.SCVPServicePolicy;
import gov.treas.pki.vss.scvp.asn1.ValPolResponse;
import gov.treas.pki.vss.status.Status;
import gov.treas.pki.vss.status.json.ConnectionPoolStats;
import gov.treas.pki.vss.status.json.Stats;

/**
 * This class provides the actual restful service endpoints, which make use of
 * SCVP for certificate validation based on the Treasury SCVP Profile.
 */
@Path("/")
public class RestServiceEndpoints {

	/**
	 * Field LOG.
	 */
	private final Logger LOG = LogManager.getLogger(RestServiceEndpoints.class);

	/**
	 * Field OID_SIZE_LIMIT
	 */
	private final int OID_SIZE_LIMIT = 50;

	/**
	 * Field PEM_SIZE_LIMIT
	 */
	private final int PEM_SIZE_LIMIT = 8192;

	/*
	 * Install the BouncyCastle JCE Provider
	 */
	BouncyCastleProvider bc = new BouncyCastleProvider();

	/**
	 * Method validate, which implements the "Long Term" SCVP Request Profile
	 * with SCVP wantBacks decoded.
	 * 
	 * @param incomingData
	 *            InputStream
	 * @return Response
	 */
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response restPost(VSSRequest request) {

		/*
		 * TODO: Now that we have a busy endpoint, we should probably break up
		 * the work.
		 * 
		 * Let's use Fork/Join to procees the request, so that we can have
		 * seperate threads for the certificate validation, versus the other
		 * tasks, such as digesting the certificate for the ID and blocking the
		 * current thread.
		 */
		Security.addProvider(bc);
		ObjectMapper mapper = new ObjectMapper();
		ASN1ObjectIdentifier oid = null;
		X509Certificate clientCert = null;
		CertificateFactory cf;
		ByteArrayInputStream bais;
		SCVPClient scvp;

		/*
		 * First, lets log the request.
		 */
		try {
			String output = mapper.writeValueAsString(request);
			LOG.info("{\"ValidationRequest\":" + output + "}");
		} catch (JsonGenerationException e) {
			LOG.error("Error converting POJO to JSON", e);
		} catch (JsonMappingException e) {
			LOG.error("Error converting POJO to JSON", e);
		} catch (IOException e) {
			LOG.error("Error converting POJO to JSON", e);
		}

		/*
		 * Ensure we have validationPolicy and clientCertificate
		 */
		if (null == request || null == request.validationPolicy || null == request.x509CertificateList
				|| null == request.wantBackList) {
			return returnVSSResponse(serviceFailure("SERVICEFAIL",
					"Request must include validationPolicy, wantBackList, and x509CertificateList", new VSSResponse()));
		}
		/*
		 * Check the validationPolicy
		 */
		if (request.validationPolicy.length() >= OID_SIZE_LIMIT) {
			return returnVSSResponse(serviceFailure("SERVICEFAIL",
					"Size limit for validationPolicy Object Identifier exceeded", new VSSResponse()));
		} else {
			try {
				oid = new ASN1ObjectIdentifier(request.validationPolicy);
			} catch (IllegalArgumentException e) {
				return returnVSSResponse(serviceFailure("SERVICEFAIL", "validationPolicy must be an Object Identifier",
						new VSSResponse()));
			}
		}
		/*
		 * Check the x509CertificateList
		 */
		List<gov.treas.pki.vss.rest.json.X509Certificate> certList = request.x509CertificateList;
		List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
		for (gov.treas.pki.vss.rest.json.X509Certificate certObj : certList) {
			String pemCert = certObj.x509Certificate;
			try {
				if (pemCert.length() >= PEM_SIZE_LIMIT) {
					return returnVSSResponse(serviceFailure("SERVICEFAIL", "Size limit for clientCertificate exceeded",
							new VSSResponse()));
				}
				byte[] certBytes = null;
				try {
					certBytes = Base64.decodeBase64(pemCert);
				} catch (Throwable e) {
					LOG.error("Error decoding certificate, returning SERVICEFAIL", e);
					return returnVSSResponse(
							serviceFailure("SERVICEFAIL", "Error decoding clientCertificate", new VSSResponse()));
				}
				if (null != certBytes) {
					cf = CertificateFactory.getInstance("X509");
					bais = new ByteArrayInputStream(certBytes);
					clientCert = (X509Certificate) cf.generateCertificate(bais);
					certificateList.add(clientCert);
				} else {
					LOG.error("Error decoding certificate base64 (null result), returning SERVICEFAIL");
					return returnVSSResponse(
							serviceFailure("SERVICEFAIL", "Error decoding clientCertificate", new VSSResponse()));
				}
			} catch (CertificateException e) {
				LOG.error("Error decoding certificate, returning SERVICEFAIL", e);
				return returnVSSResponse(
						serviceFailure("SERVICEFAIL", "Error decoding clientCertificate", new VSSResponse()));
			}
		}
		List<String> supportedWantBacks = new ArrayList<String>();
		supportedWantBacks.add("certPath");
		supportedWantBacks.add("revocationInfo");

		/*
		 * Check the wantBackList
		 */
		List<WantBackTypeToken> wantBackList = request.wantBackList;
		for (WantBackTypeToken wantBack : wantBackList) {
			if (!supportedWantBacks.contains(wantBack.wantBackTypeToken)) {
				return returnVSSResponse(serviceFailure("SERVICEFAIL",
						"Unknown/Unsupported wantBackTypeToken value: " + wantBack.wantBackTypeToken,
						new VSSResponse()));
			}
		}
		/*
		 * Now we will validate the certificate using SCVP.
		 */
		scvp = new SCVPClient();

		/*
		 * Process SCVP request for all certificates in the list, and provide a
		 * consolidated response
		 */
		clientCert = certificateList.get(0);
		List<VSSResponse> responseList = new ArrayList<VSSResponse>();
		/*
		 * Now we will perform the SCVP validation for each certificate
		 */
		for (X509Certificate cert : certificateList) {
			try {
				responseList.add(scvp.validate(cert, oid, wantBackList, new VSSResponse()));
			} catch (NoClassDefFoundError e) {
				LOG.error("Error loading API, likely reflection error, returning SERVICEFAIL", e);
				return returnVSSResponse(
						serviceFailure("SERVICEFAIL", "Error with Certificate Validation API", new VSSResponse()));
			}
		}
		/*
		 * Now, we will inspect the responses, and return a consolidated
		 * response
		 */
		VSSResponse result = new VSSResponse();
		boolean successfulResponse = false;
		TransactionResult tResult = new TransactionResult();
		tResult.transactionResultToken = "SERVICEFAIL";
		tResult.transactionResultText = "No more info.";
		List<ResultByCertificate> resultsByCertificateList = new ArrayList<ResultByCertificate>();
		for (VSSResponse response : responseList) {
			if (response.transactionResult.transactionResultToken.equals("SUCCESS")) {
				successfulResponse = true;
			} else {
				tResult.transactionResultToken = response.transactionResult.transactionResultToken;
				tResult.transactionResultText = response.transactionResult.transactionResultText;
			}
			/*
			 * Logic to log each individual response, if needed.
			 */
//			try {
//				String output = mapper.writeValueAsString(response);
//				LOG.info("{\"IndividualResponse\":" + output + "}");
//			} catch (JsonGenerationException e) {
//				LOG.error("Error converting POJO to JSON", e);
//			} catch (JsonMappingException e) {
//				LOG.error("Error converting POJO to JSON", e);
//			} catch (IOException e) {
//				LOG.error("Error converting POJO to JSON", e);
//			}
			ResultByCertificate resultByCertificate = new ResultByCertificate();
			if (null != response.validationResult) {
				resultByCertificate = response.validationResult.resultsByCertificateList.get(0);
			}
			resultsByCertificateList.add(resultByCertificate);
		}
		if (successfulResponse) {
			tResult.transactionResultToken = "SUCCESS";
			tResult.transactionResultText = "Validation Operation Completed Successfully";
			result.transactionResult = tResult;
			ValidationResult validationResult = new ValidationResult();
			validationResult.resultsByCertificateList = resultsByCertificateList;
			result.validationResult = validationResult;
		} else {
			result.transactionResult = tResult;
			ValidationResult validationResult = new ValidationResult();
			validationResult.resultsByCertificateList = resultsByCertificateList;
			result.validationResult = validationResult;
		}
		return returnVSSResponse(result);
	}

	public Response returnVSSResponse(VSSResponse result) {

		ObjectMapper mapper = new ObjectMapper();
		/*
		 * Return the result
		 */
		try {
			String output = mapper.writeValueAsString(result);
			LOG.info("{\"ValidationResponse\":" + output + "}");
		} catch (JsonGenerationException e) {
			LOG.error("Error converting POJO to JSON", e);
		} catch (JsonMappingException e) {
			LOG.error("Error converting POJO to JSON", e);
		} catch (IOException e) {
			LOG.error("Error converting POJO to JSON", e);
		}
		return Response.status(HttpServletResponse.SC_OK).entity(result).build();
	}

	private VSSResponse serviceFailure(String transactionResultToken, String transactionResultText,
			VSSResponse result) {
		TransactionResult tResult = new TransactionResult();
		tResult.transactionResultToken = transactionResultToken;
		tResult.transactionResultText = transactionResultText;
		result.transactionResult = tResult;
		return result;
	}

	@GET
	@Path("/status")
	@Produces(MediaType.APPLICATION_JSON)
	public Response status() {
		/*
		 * For our health check, we are going
		 * to send an SCVP Policy Request
		 */
		SCVPClient scvp = new SCVPClient();
		ValPolResponse vpResponse = scvp.getServerPolicy();
		SCVPServicePolicy policy = SCVPServicePolicy.getInstance();
		if (null != vpResponse) {
			policy.setValPolResponse(vpResponse);
			/*
			 * TODO: In the future, we will do something with the policy.  See TODO above.
			 */
		}
		Status status = Status.getInstance();
		HttpClient client = HttpClient.getInstance();
		PoolStats cmStats = client.getPoolStats();
		ConnectionPoolStats poolStats = new ConnectionPoolStats();
		poolStats.available = cmStats.getAvailable();
		poolStats.leased = cmStats.getLeased();
		poolStats.max = cmStats.getMax();
		poolStats.pending = cmStats.getPending();
		Stats stats = new Stats();
		stats.connectionPoolStats = poolStats;
		ObjectMapper mapper = new ObjectMapper();
		/*
		 * Return the result
		 */
		try {
			String output = mapper.writeValueAsString(stats);
			LOG.info("{\"Stats\":" + output + "}");
		} catch (JsonGenerationException e) {
			LOG.error("Error converting POJO to JSON", e);
		} catch (JsonMappingException e) {
			LOG.error("Error converting POJO to JSON", e);
		} catch (IOException e) {
			LOG.error("Error converting POJO to JSON", e);
		}
		if (status.serviceAvailable()) {
			return Response.status(HttpServletResponse.SC_OK).entity(stats).build();
		} else {
			return Response.status(HttpServletResponse.SC_SERVICE_UNAVAILABLE).entity(stats).build();
		}
	}

}