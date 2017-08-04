package gov.treas.pki.vss.status;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Status {

	private volatile static Status INSTANCE = null;
	private final Logger LOG = LogManager.getLogger(Status.class);
	private volatile int serviceFailCount;
	private volatile boolean serviceAvailable;

	/**
	 * Field MAXSERVICEFAIL.  The maximum number of
	 * failures received before the service is marked
	 * unavailable.
	 */
	public static final int MAXSERVICEFAIL = 5;

	/**
	 * 
	 * @return Status
	 */
	public static Status getInstance() {
		if (INSTANCE == null) {
			synchronized (Status.class) {
				if (INSTANCE == null) {
					INSTANCE = new Status();
				}
			}
		}
		return INSTANCE;
	}

	private Status() {
		LOG.info("Initializing Server Status Singleton");
		serviceFailCount = 0;
		serviceAvailable = true;
	}

	public void serviceFail() {
		serviceFailCount++;
		if (serviceFailCount >= MAXSERVICEFAIL) {
			serviceAvailable = false;
		}
	}

	public void markServiceAvailable() {
		serviceAvailable = true;
		serviceFailCount = 0;
	}

	public boolean serviceAvailable() {
		return serviceAvailable;
	}


}
