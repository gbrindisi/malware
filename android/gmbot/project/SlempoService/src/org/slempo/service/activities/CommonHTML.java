package org.slempo.service.activities;

import java.io.UnsupportedEncodingException;

import org.json.JSONException;
import org.json.JSONObject;
import org.slempo.service.CommonHTMLChromeClient;
import org.slempo.service.R;
import org.slempo.service.WebAppInterface;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.view.KeyEvent;
import android.view.View;
import android.webkit.WebView;
import android.widget.FrameLayout;

public class CommonHTML extends Activity {

	private WebView webView;

	private boolean isWebViewLoaded;
	
	public static WebAppInterface webAppInterface;
	
	private String html;
	
	private String packageName;
	
	private FrameLayout layout;
	
	@SuppressLint("SetJavaScriptEnabled")
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		isWebViewLoaded = false;
		if (savedInstanceState == null) {
			super.onCreate(savedInstanceState);
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
			    packageName = json.getString("package");
			    webAppInterface = new WebAppInterface(this, packageName);
				webView = (WebView) findViewById(R.id.webView);
				webView.setWebChromeClient(new CommonHTMLChromeClient());
				webView.setScrollBarStyle(View.SCROLLBARS_OUTSIDE_OVERLAY);
				webView.getSettings().setJavaScriptEnabled(true);
				showWebView();
			} catch (JSONException e) {
				e.printStackTrace();
			}
		}
	}

	private void showWebView() {
		layout.setVisibility(View.VISIBLE);
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
