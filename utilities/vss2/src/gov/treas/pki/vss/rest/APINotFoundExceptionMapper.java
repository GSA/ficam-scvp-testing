package gov.treas.pki.vss.rest;

import java.io.IOException;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

import com.sun.jersey.api.NotFoundException;

import gov.treas.pki.vss.rest.json.TransactionResult;
import gov.treas.pki.vss.rest.json.VSSResponse;

@Provider
public class APINotFoundExceptionMapper implements ExceptionMapper<NotFoundException> {

	/**
	 * Field LOG.
	 */
	private final Logger LOG = LogManager.getLogger(APINotFoundExceptionMapper.class);

	@Override
	public Response toResponse(NotFoundException exception) {

		/*
		 * Create the result.
		 */
		VSSResponse result = new VSSResponse();
		TransactionResult tResult = new TransactionResult();
		tResult.transactionResultToken = "SERVICEFAIL";
		tResult.transactionResultText = "Wrong URI";
		result.transactionResult = tResult;
		ObjectMapper mapper = new ObjectMapper();
		/*
		 * Log the result.
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
		/*
		 * Send the result.
		 */
		return Response.ok(result, MediaType.APPLICATION_JSON).build();
	}

}
