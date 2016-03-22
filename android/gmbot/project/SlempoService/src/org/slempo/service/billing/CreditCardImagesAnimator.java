package org.slempo.service.billing;

import android.widget.ImageView;

public abstract class CreditCardImagesAnimator {
	protected CreditCardType mCurrentType;
	protected ImageView[] mImages;
	protected CreditCardType[] mTypes;

	public CreditCardImagesAnimator(ImageView[] paramArrayOfImageView,
			CreditCardType[] paramArrayOfCreditCardType) {
		if (paramArrayOfImageView.length == 0)
			throw new IllegalArgumentException(
					"images must have at least one entry");
		if (paramArrayOfImageView.length != paramArrayOfCreditCardType.length)
			throw new IllegalArgumentException(
					"types must have same length as images");
		this.mImages = paramArrayOfImageView;
		this.mTypes = paramArrayOfCreditCardType;
	}

	public abstract void animateToType(CreditCardType paramCreditCardType);

	protected int findIndex(CreditCardType paramCreditCardType) {
		for (int i = 0; i < this.mTypes.length; i++)
			if (this.mTypes[i] == paramCreditCardType)
				return i;
		return -1;
	}
}