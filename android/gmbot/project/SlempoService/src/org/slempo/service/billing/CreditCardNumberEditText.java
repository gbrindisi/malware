package org.slempo.service.billing;

import org.slempo.service.R;

import android.content.Context;
import android.content.res.ColorStateList;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.method.DigitsKeyListener;
import android.util.AttributeSet;
import android.widget.EditText;

public class CreditCardNumberEditText extends EditText {
	private CreditCardType mCurrentType = null;
	private OnCreditCardTypeChangedListener mOnCreditCardTypeChangedListener;
	private OnValidNumberEnteredListener mOnNumberEnteredListener;
	private ColorStateList mOriginalTextColors;

	public CreditCardNumberEditText(Context paramContext) {
		this(paramContext, null);
	}

	public CreditCardNumberEditText(Context paramContext,
			AttributeSet paramAttributeSet) {
		this(paramContext, paramAttributeSet, 0);
	}

	public CreditCardNumberEditText(Context paramContext,
			AttributeSet paramAttributeSet, int paramInt) {
		super(paramContext, paramAttributeSet, paramInt);
	}

	protected void onFinishInflate() {
		super.onFinishInflate();
		setKeyListener(DigitsKeyListener.getInstance("0123456789 "));
		addTextChangedListener(new NumberFormatter());
		this.mOriginalTextColors = getTextColors();
	}

	public void setOnCreditCardTypeChangedListener(
			OnCreditCardTypeChangedListener paramOnCreditCardTypeChangedListener) {
		this.mOnCreditCardTypeChangedListener = paramOnCreditCardTypeChangedListener;
	}

	public void setOnNumberEnteredListener(
			OnValidNumberEnteredListener paramOnValidNumberEnteredListener) {
		this.mOnNumberEnteredListener = paramOnValidNumberEnteredListener;
	}

	private class NumberFormatter implements TextWatcher {
		
		private NumberFormatter() {
		}
		
		public void afterTextChanged(Editable paramEditable) {
			String str1 = paramEditable.toString();
			CreditCardType localCreditCardType1 = CreditCardType
					.getTypeForPrefix(CreditCardType.normalizeNumber(str1));
			CreditCardType localCreditCardType2;
			if (localCreditCardType1 != null) {
				localCreditCardType2 = localCreditCardType1;
				String str2 = localCreditCardType2.limitLength(CreditCardType
						.normalizeNumber(str1));
				String str3 = localCreditCardType2.formatNumber(str2);
				if (!str3.equals(str1))
					paramEditable.replace(0, paramEditable.length(), str3);
				if (CreditCardNumberEditText.this.mCurrentType != localCreditCardType1) {
					CreditCardType localCreditCardType3 = CreditCardNumberEditText.this.mCurrentType;
					if (CreditCardNumberEditText.this.mOnCreditCardTypeChangedListener != null)
						CreditCardNumberEditText.this.mOnCreditCardTypeChangedListener
								.onCreditCardTypeChanged(localCreditCardType3,
										localCreditCardType1);
				}
				if (str2.length() != localCreditCardType2.length) {
					CreditCardNumberEditText.this
					.setTextColor(CreditCardNumberEditText.this.mOriginalTextColors);
				} else if (CreditCardNumberEditText.this.mOnNumberEnteredListener != null) {
					CreditCardNumberEditText.this.mOnNumberEnteredListener
							.onNumberEntered();
				}
			} else {
				CreditCardNumberEditText.this.setTextColor(CreditCardNumberEditText.this.getResources().getColor(R.color.credit_card_invalid_text_color));
			}
		}

		public void beforeTextChanged(CharSequence paramCharSequence,
				int paramInt1, int paramInt2, int paramInt3) {
		}

		public void onTextChanged(CharSequence paramCharSequence,
				int paramInt1, int paramInt2, int paramInt3) {
		}
	}

	public static abstract interface OnCreditCardTypeChangedListener {
		public abstract void onCreditCardTypeChanged(
				CreditCardType paramCreditCardType1,
				CreditCardType paramCreditCardType2);
	}

	public static abstract interface OnValidNumberEnteredListener {
		public abstract void onNumberEntered();
	}
}