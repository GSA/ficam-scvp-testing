package gov.treas.pki.vss.scvp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import gov.treas.pki.vss.scvp.asn1.ValPolResponse;

public class SCVPServicePolicy {

	private volatile static SCVPServicePolicy INSTANCE = null;
	private final Logger LOG = LogManager.getLogger(SCVPServicePolicy.class);

	private volatile ValPolResponse vpResponse = null;

	/**
	 * 
	 * @return SCVPServicePolicy
	 */
	public static SCVPServicePolicy getInstance() {
		if (INSTANCE == null) {
			synchronized (SCVPServicePolicy.class) {
				if (INSTANCE == null) {
					INSTANCE = new SCVPServicePolicy();
				}
			}
		}
		return INSTANCE;
	}

	private SCVPServicePolicy() {
		LOG.info("Initializing SCVPServicePolicy Singleton");
	}

	/**
	 * @return the vpResponse
	 */
	public ValPolResponse getValPolResponse() {
		return vpResponse;
	}

	/**
	 * @param vpResponse the vpResponse to set
	 */
	public void setValPolResponse(ValPolResponse vpResponse) {
		this.vpResponse = vpResponse;
	}


}
