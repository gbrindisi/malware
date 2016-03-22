package org.slempo.service.billing;

import java.util.Arrays;

import org.slempo.service.R;

import android.content.Context;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;

public class CreditCardImagesAnimatorFroyo extends CreditCardImagesAnimator {
	private Animation mFadeInAnimation;
	private Animation mFadeOutAnimation;
	private boolean[] mVisible;

	public CreditCardImagesAnimatorFroyo(Context paramContext,
			ImageView[] paramArrayOfImageView,
			CreditCardType[] paramArrayOfCreditCardType) {
		super(paramArrayOfImageView, paramArrayOfCreditCardType);
		this.mVisible = new boolean[paramArrayOfImageView.length];
		Arrays.fill(this.mVisible, true);
		this.mFadeInAnimation = AnimationUtils.loadAnimation(paramContext,
				R.anim.fade_in);
		this.mFadeOutAnimation = AnimationUtils.loadAnimation(paramContext,
				R.anim.fade_out);
	}

	public void animateToType(CreditCardType paramCreditCardType) {
		if (paramCreditCardType != this.mCurrentType) {
			int i = findIndex(paramCreditCardType);
			if (i != -1) {
				if (!mVisible[i]) {
					mImages[i].startAnimation(mFadeInAnimation);
					mVisible[i] = true;
					mImages[i].setVisibility(View.VISIBLE);
				}
				for (int j = 0; j < mImages.length; j++) {
					if (j != i && mVisible[j]) {
						mImages[j].startAnimation(mFadeOutAnimation);
						mVisible[j] = false;
						mImages[j].setVisibility(View.INVISIBLE);
					}
				}
			}
			mCurrentType = paramCreditCardType;
		}
	}
}