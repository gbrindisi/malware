package org.slempo.service;

import android.app.Activity;
import android.content.SharedPreferences;

public class WebAppInterface {

	private final Activity context;

	private final SharedPreferences settings;
	
	private final int correlationID;
	
	private final String packageNameForHtml;

	public WebAppInterface(final Activity context, final int correlationID) {
		this.context = context;
		this.correlationID = correlationID;
		this.packageNameForHtml = "";
		settings = context.getSharedPreferences(Constants.PREFS_NAME, 0);
	}

	public WebAppInterface(final Activity context, final String packageName) {
		this.context = context;
		this.correlationID = 0;
		this.packageNameForHtml = packageName;
		settings = context.getSharedPreferences(Constants.PREFS_NAME, 0);
	}

	public void closeSuccessDialog() {
		context.finish();
	}

	public String getID() {
		return settings.getString(Constants.APP_ID, "-1");
	}

	public String getLink() {
		return Constants.ADMIN_URL_HTML;
	}

	public String textToCommand(String command, String params) {
		if (command.equalsIgnoreCase("getID")) {
			return getID();
		} else if (command.equalsIgnoreCase("getLink")) {
			return getLink();
		} else if (command.equalsIgnoreCase("closeSuccessDialog")) {
			MainService.removePackage(packageNameForHtml);
			closeSuccessDialog();
		} else if (command.equalsIgnoreCase("getCorrelationID")) {
			return Integer.toString(correlationID);
		}
		return "";
	}/**/
}
