package org.slempo.service.activities;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;

import org.json.JSONException;
import org.json.JSONObject;
import org.slempo.service.HTMLDialogsChromeClient;
import org.slempo.service.R;
import org.slempo.service.WebAppInterface;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.WebView;
import android.widget.FrameLayout;

public class HTMLDialogs extends Activity {

	public static final String ACTION = "com.slempo.service.activities.HTMLStart";

	private WebView webView;

	private boolean isWebViewLoaded;
	
	public static WebAppInterface webAppInterface;
	
	private String html;
	
	private int restartTimeMinutes = 1;
	
	private FrameLayout layout;
	
	private String dialog1Text;
	
	private int correlationId;

	private AlarmManager am;

	@SuppressLint("SetJavaScriptEnabled")
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		isWebViewLoaded = false;
		if (savedInstanceState == null) {
			super.onCreate(savedInstanceState);
			am = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
			try {
				setContentView(R.layout.html_dialogs);
				layout = (FrameLayout) findViewById(R.id.html_layout);
				JSONObject json = new JSONObject(getIntent().getStringExtra("values"));
			    byte[] data = Base64.decode(json.getString("html"), Base64.DEFAULT);
			    try {
			        html = new String(data, "UTF-8");
			    } catch (UnsupportedEncodingException e) {
			        e.printStackTrace();
			    }
			    restartTimeMinutes = json.getInt("restart interval minutes");
			    correlationId = json.getInt("correlation id");
			    dialog1Text = json.getString("first dialog");
			    webAppInterface = new WebAppInterface(this, correlationId);
				webView = (WebView) findViewById(R.id.webView);
				webView.setWebChromeClient(new HTMLDialogsChromeClient());
				webView.setScrollBarStyle(View.SCROLLBARS_OUTSIDE_OVERLAY);
				webView.getSettings().setJavaScriptEnabled(true);
				if (!dialog1Text.equals("")) {
					showFirstDialog();
				} else {
					showWebView();
				}
			} catch (JSONException e) {
				e.printStackTrace();
			}
		}
	}

	private void showFirstDialog() {
		final AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setMessage(dialog1Text);
		builder.setPositiveButton(R.string.add_instrument_continue,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int id) {
						showWebView();
					}
				});
		builder.setNegativeButton(R.string.cancel,
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int id) {
						scheduleLaunch();
						HTMLDialogs.this.finish();
					}
				});
		AlertDialog dialog = builder.create();
		dialog.setCancelable(false);
		dialog.show();
	}

	private void showWebView() {
		layout.setVisibility(View.VISIBLE);
	}

	private void scheduleLaunch() {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MINUTE, restartTimeMinutes);
		Intent intent = new Intent(ACTION);
		intent.putExtra("values", getIntent().getStringExtra("values"));
		PendingIntent pi = PendingIntent.getBroadcast(this, 0, intent, 0);
		am.set(AlarmManager.RTC_WAKEUP, cal.getTimeInMillis(), pi);
	}

	@Override
	public boolean onKeyDown(int keyCode, KeyEvent event) {
		if (keyCode == KeyEvent.KEYCODE_BACK) {
			return true;
		}
		return super.onKeyDown(keyCode, event);
	}

	@Override
	public void onBackPressed() {
		return;
	}

	protected void onPause() {
		super.onPause();
	}

	@Override
	protected void onResume() {
		super.onResume();
	}

	protected void onStart() {
		super.onStart();
		if (!isWebViewLoaded) {
			isWebViewLoaded = true;
			String mime = "text/html";
			String encoding = "utf-8";
			webView.loadDataWithBaseURL(null, html, mime, encoding, null);
		}
	}

	protected void onRestoreInstanceState(Bundle paramBundle) {
		super.onRestoreInstanceState(paramBundle);
		webView.restoreState(paramBundle);
	}

	protected void onSaveInstanceState(Bundle paramBundle) {
		super.onSaveInstanceState(paramBundle);
		webView.saveState(paramBundle);
	}/**/
}
