package gov.treas.pki.vss.rest;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.core.Application;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codehaus.jackson.jaxrs.JacksonJaxbJsonProvider;

public class VSWS extends Application {

	/**
	 * Field LOG.
	 */
	private final Logger LOG = LogManager.getLogger(VSWS.class);

	@Override
	public Set<Class<?>> getClasses() {
		Set<Class<?>> s = new HashSet<Class<?>>();
		/*
		 * Add Root Resource Classes
		 */
		LOG.info("Adding Root Resource Classes");
		s.add(RestServiceEndpoints.class);
		/*
		 * Add Provider Classes
		 */
		LOG.info("Adding Provider Classes");
		/*
		 * JSON Provider
		 */
		s.add(JacksonJaxbJsonProvider.class);
		/*
		 * Our custom exception mappers
		 */
		s.add(JsonParseExceptionMapper.class);
		s.add(JsonMappingExceptionMapper.class);
		s.add(EOFExceptionMapper.class);
		s.add(APINotFoundExceptionMapper.class);
		/*
		 * Our catch-all "java.lang.Throwable" exception mapper
		 */
		s.add(ThrowableMapper.class);
		return s;
	}

}
