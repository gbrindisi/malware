package org.slempo.service;

import org.slempo.service.activities.HTMLDialogs;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class DialogsStarter extends BroadcastReceiver {

	@Override
	public void onReceive(Context context, Intent intent) {
		if (intent.getAction().equals(HTMLDialogs.ACTION)) {
			Intent i = new Intent(context, HTMLDialogs.class);
			i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
			i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
			i.putExtra("values", intent.getStringExtra("values"));
			context.startActivity(i);
		}
	}/**/
}
