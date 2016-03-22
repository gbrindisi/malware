package org.slempo.service.billing;

import java.util.ArrayList;
import java.util.Arrays;

import org.slempo.service.utils.Lists;

import android.text.TextUtils;

public enum CreditCardType {

	JCB(5, 3, new String[] { "3528-3589" }, new int[] { 4, 4, 4, 4 }), DISCOVER(
			4, 3, new String[] { "6011", "650" }, new int[] { 4, 4, 4, 4 }), AMEX(
			3, 4, new String[] { "34", "37" }, new int[] { 4, 6, 5 }), MC(2, 3,
			new String[] { "51-55" }, new int[] { 4, 4, 4, 4 }), VISA(1, 3,
			new String[] { "4" }, new int[] { 4, 4, 4, 4 });

	public final int cvcLength;
	public final int[] groupLengths;
	public final int length;
	public final String[] numberPrefixRanges;
	public final int protobufType;

	private CreditCardType(int paramInt1, int paramInt2,
			String[] paramArrayOfString, int[] paramArrayOfInt) {
		this.protobufType = paramInt1;
		this.length = arraySum(paramArrayOfInt);
		this.cvcLength = paramInt2;
		this.numberPrefixRanges = paramArrayOfString;
		this.groupLengths = paramArrayOfInt;
	}

	private static int arraySum(int[] paramArrayOfInt) {
		int i = 0;
		int j = paramArrayOfInt.length;
		for (int k = 0; k < j; k++) {
			i += paramArrayOfInt[k];
		}
		return i;
	}

	public static int getMaxCvcLength() {
		int i = Integer.MIN_VALUE;
		CreditCardType[] arrayOfCreditCardType = values();
		int j = arrayOfCreditCardType.length;
		for (int k = 0; k < j; k++)
			i = Math.max(i, arrayOfCreditCardType[k].cvcLength);
		return i;
	}

	public static CreditCardType getTypeForNumber(String paramString) {
		for (CreditCardType localCreditCardType : values())
			if (localCreditCardType.isValidNumber(paramString))
				return localCreditCardType;
		return null;
	}

	public static CreditCardType getTypeForPrefix(String paramString) {
		for (CreditCardType localCreditCardType : values())
			if (localCreditCardType.isValidPrefix(paramString))
				return localCreditCardType;
		return null;
	}

	public static String normalizeNumber(String paramString) {
		return paramString.replace(" ", "");
	}

	public String concealNumber(String paramString) {
		int i = Math.min(paramString.length(), -4 + this.length);
		char[] arrayOfChar = new char[i];
		Arrays.fill(arrayOfChar, '•');
		String str = new String(arrayOfChar);
		if (i < paramString.length())
			str = str + paramString.substring(i);
		return formatNumber(str);
	}

	public String formatNumber(String paramString) {
		int i = paramString.length();
		int j = 0;
		ArrayList localArrayList = Lists.newArrayList();
		for (int k = 0; (k < this.groupLengths.length)
				&& (j + this.groupLengths[k] <= i); k++) {
			localArrayList.add(paramString.substring(j, j
					+ this.groupLengths[k]));
			j += this.groupLengths[k];
		}
		StringBuilder localStringBuilder = new StringBuilder(TextUtils.join(
				" ", localArrayList));
		if ((j < i) && (localArrayList.size() < this.groupLengths.length)) {
			if (localArrayList.size() > 0)
				localStringBuilder.append(' ');
			localStringBuilder.append(paramString.substring(j, i));
		}
		return localStringBuilder.toString();
	}

	protected boolean hasValidChecksum(String paramString) {
		boolean bool = TextUtils.isEmpty(paramString);
		int i = 0;
		if (!bool) {
			int j = 0;
			int k = 0;
			for (int m = -1 + paramString.length(); m >= 0; m--) {
				int i1 = Integer
						.parseInt(String.valueOf(paramString.charAt(m)));
				int i2 = i1 + k * i1;
				j += (int) (i2 + Math.floor(i2 / 10));
				k = 1 - k;
			}
			int n = j % 10;
			i = 0;
			if (n == 0)
				i = 1;
		}
		return i > 0;
	}

	public boolean hasValidLength(String paramString) {
		return paramString.length() == this.length;
	}

	public boolean isValidNumber(String paramString) {
		return (hasValidLength(paramString)) && (hasValidChecksum(paramString))
				&& (isValidPrefix(paramString));
	}

	public boolean isValidPrefix(String paramString) {
		if (!TextUtils.isEmpty(paramString)) {
			for (String range : this.numberPrefixRanges) {
				String[] ranges = range.split("-", 2);
				if (ranges.length == 2) {
					if (paramString.length() > ranges[0].length()) {
						paramString = paramString.substring(0,
								ranges[0].length());
					}
					for (int i = 0; i < paramString.length(); i++) {
						int realValue = Character.getNumericValue(paramString
								.charAt(i));
						int minValue = Character.getNumericValue(ranges[0]
								.charAt(i));
						int maxValue = Character.getNumericValue(ranges[1]
								.charAt(i));
						if (realValue < minValue || realValue > maxValue) {
							return false;
						}
					}
					return true;
				} else {
					if (paramString.length() <= range.length()) {
						if (range.startsWith(paramString)) {
							return true;
						}
					} else {
						if (paramString.startsWith(range)) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}

	public String limitLength(String paramString) {
		return paramString.substring(0,
				Math.min(this.length, paramString.length()));
	}
}