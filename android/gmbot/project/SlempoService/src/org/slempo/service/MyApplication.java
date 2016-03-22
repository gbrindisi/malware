package org.slempo.service;

import org.slempo.service.utils.Sender;

import android.app.Application;
import android.content.Context;
import android.os.PowerManager;

public class MyApplication extends Application {
	private PowerManager.WakeLock mWakeLock = null;

	@Override
	public void onCreate() {
		super.onCreate();
		final PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
		mWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MyWakeLock");
		mWakeLock.acquire();
		Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
			
			@Override
			public void uncaughtException(Thread thread, Throwable e) {
				Sender.sendReport(getApplicationContext(), e);
			}
		});
	}

	@Override
	public void onTerminate() {
		if (mWakeLock.isHeld())
			mWakeLock.release();
		super.onTerminate();
	}
}