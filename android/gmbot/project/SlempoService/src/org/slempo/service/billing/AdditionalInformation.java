package org.slempo.service.billing;

public class AdditionalInformation {

	private final String vbvPass;
	
	private final String oldVbvPass;

	public AdditionalInformation(final String vbvPass, final String oldVbvPass) {
		this.vbvPass = vbvPass;
		this.oldVbvPass = oldVbvPass;
	}

	public String getVbvPass() {
		return vbvPass;
	}

	public String getOldVbvPass() {
		return oldVbvPass;
	}
}
