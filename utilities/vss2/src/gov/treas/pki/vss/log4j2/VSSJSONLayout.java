package gov.treas.pki.vss.log4j2;

import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.NoSuchElementException;

import javax.json.Json;
import javax.json.JsonBuilderFactory;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.stream.JsonParsingException;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.AbstractStringLayout;

@Plugin(name = "VSSJSONLayout", category = "Core", elementType = "layout", printObject = false)
public class VSSJSONLayout extends AbstractStringLayout {

	private static final JsonBuilderFactory BUILDER = Json.createBuilderFactory(null);
	private static String hostName;
	static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";

	static {
		try {
			hostName = InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			hostName = "unknown-host";
		}
	}

	protected VSSJSONLayout(Charset charset) {
		super(charset);
	}

	@PluginFactory
	public static VSSJSONLayout createLayout(@PluginAttribute(value = "charset", defaultString = "UTF-8") Charset charset) {
		return new VSSJSONLayout(charset);
	}

	@Override
	public String toSerializable(LogEvent event) {
		markEvent();
		return format(event);
	}

	public final String format(final LogEvent event) {
		final SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
		final String eventDateString = dateFormat.format(new Date(event.getTimeMillis()));

		/* test to see if this is JSON */
		JsonObject jmessage = getJSON(event.getMessage().getFormattedMessage());
		if (null != jmessage) {
			return BUILDER.createObjectBuilder().add("@timestamp", eventDateString)
					.add("@message", jmessage)
					.add("@source", event.getLoggerName())
					.add("@source_host", hostName)
					.add("@fields", encodeFields(event)).build().toString()
					+ "\n";
		} else {
			return BUILDER.createObjectBuilder().add("@timestamp", eventDateString)
				.add("@message", event.getMessage().toString())
				.add("@source", event.getLoggerName())
				.add("@source_host", hostName)
				.add("@fields", encodeFields(event)).build().toString()
				+ "\n";
		}
	}

	/*
	 * Test to check if a string is actually a JSON message,
	 * return the object.  Returns null if it is not a JsonObject.
	 */
	public JsonObject getJSON(String message) {

		JsonObject jobj = null;
		try {
			JsonReader reader = Json.createReader(new StringReader(message));
			jobj = reader.readObject();
		} catch (JsonParsingException e) {
		} catch (JsonException e) {
		} catch (NoSuchElementException e) {
		}
		return jobj;

	}
	
	/**
	 * Enocde all addtional fields.
	 * 
	 * @param record
	 *            the log record
	 * @return objectBuilder
	 */
	final JsonObjectBuilder encodeFields(final LogEvent event) {
		final SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
		final String eventDateString = dateFormat.format(new Date(event.getTimeMillis()));

		JsonObjectBuilder builder = BUILDER.createObjectBuilder();
		builder.add("timestamp", eventDateString);
		builder.add("level", event.getLevel().toString());
		builder.add("line_number", getLineNumber(event));
		addSourceClassName(event, builder);
		addSourceMethodName(event, builder);
		addThrowableInfo(event, builder);
		return builder;
	}

	/**
	 * Format the stackstrace.
	 * 
	 * @param record
	 *            the logrecord which contains the stacktrace
	 * @param builder
	 *            the json object builder to append
	 */
	final void addThrowableInfo(final LogEvent event,
			final JsonObjectBuilder builder) {
		if (event.getThrown() != null) {
			if (event.getSource() != null) {
				builder.add("exception_class", event.getThrown().getClass()
						.getName());
			}
			if (event.getThrown().getMessage() != null) {
				builder.add("exception_message", event.getThrown()
						.getMessage());
			}
			addStacktraceElements(event, builder);
		}
	}

	/**
	 * Get the line number of the exception.
	 * 
	 * @param record
	 *            the logrecord
	 * @return the line number
	 */
	final int getLineNumber(final LogEvent event) {
		final int lineNumber;
		if (event.getThrown() != null) {
			lineNumber = getLineNumberFromStackTrace(event.getThrown()
					.getStackTrace());
		} else {
			lineNumber = event.getSource().getLineNumber();
		}
		return lineNumber;
	}

	/**
	 * Gets line number from stack trace.
	 * 
	 * @param traces
	 *            all stack trace elements
	 * @return line number of the first stacktrace.
	 */
	final int getLineNumberFromStackTrace(final StackTraceElement[] traces) {
		final int lineNumber;
		if (traces.length > 0 && traces[0] != null) {
			lineNumber = traces[0].getLineNumber();
		} else {
			lineNumber = 0;
		}
		return lineNumber;
	}

	final void addValue(final JsonObjectBuilder builder, final String key,
			final String value) {
		if (value != null) {
			builder.add(key, value);
		} else {
			builder.add(key, "null");
		}
	}

	private void addSourceMethodName(final LogEvent event,
			final JsonObjectBuilder builder) {
		addValue(builder, "method", event.getSource().getMethodName());
	}

	private void addSourceClassName(final LogEvent event,
			final JsonObjectBuilder builder) {
		addValue(builder, "class", event.getSource().getClassName());
	}

	private void addStacktraceElements(final LogEvent event,
			final JsonObjectBuilder builder) {
		final StringWriter sw = new StringWriter();
		event.getThrown().printStackTrace(new PrintWriter(sw));
		builder.add("stacktrace", sw.toString());
	}

}