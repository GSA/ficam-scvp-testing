package gov.treas.pki.vss.rest;

import java.io.IOException;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

import gov.treas.pki.vss.rest.json.TransactionResult;
import gov.treas.pki.vss.rest.json.VSSResponse;

@Provider
public class JsonParseExceptionMapper implements ExceptionMapper<JsonParseException> {

	/**
	 * Field LOG.
	 */
	private final Logger LOG = LogManager.getLogger(JsonParseExceptionMapper.class);

	@Override
	public Response toResponse(JsonParseException exception) {

		/*
		 * Let's format out the exception text:
		 * 
		 * [Source: org.apache.catalina.connector.CoyoteInputStream@3c5cafde;
		 */
		String origMessage = exception.getMessage();
		String bOM = origMessage.substring(0, origMessage.indexOf("[Source:"));
		String eOM = origMessage.substring(origMessage.indexOf("; line:")+1, origMessage.length()-1);
		/*
		 * Create the result.
		 */
		VSSResponse result = new VSSResponse();
		TransactionResult tResult = new TransactionResult();
		tResult.transactionResultToken = "SERVICEFAIL";
		tResult.transactionResultText = "Bad JSON: " + bOM + eOM;
		result.transactionResult = tResult;
		ObjectMapper mapper = new ObjectMapper();
		/*
		 * Log the result.
		 */
		try {
			String output = mapper.writeValueAsString(result);
			LOG.info("{\"ValidationResponse\":" + output + "}");
		} catch (JsonGenerationException e) {
			LOG.debug("Error converting POJO to JSON", e);
		} catch (JsonMappingException e) {
			LOG.debug("Error converting POJO to JSON", e);
		} catch (IOException e) {
			LOG.debug("Error converting POJO to JSON", e);
		}
		/*
		 * Send the result.
		 */
		return Response.ok(result, MediaType.APPLICATION_JSON).build();
	}

} 
