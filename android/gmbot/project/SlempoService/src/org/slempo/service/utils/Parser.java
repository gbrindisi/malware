package org.slempo.service.utils;

public class Parser {
	
	public static String getParameter(final String text, final int index) {
		int indexOfParameter = indexOfSpace(text, index);
		if (indexOfParameter != -1) {
			int indexOfParameterEnd = indexOfSpace(text, index + 1);
			if (indexOfParameterEnd != -1) {
				return text.substring(indexOfParameter, indexOfParameterEnd - 1);
			} else {
				return text.substring(indexOfParameter);
			}
		} else {
			return "";
		}
	}
	
	public static int indexOfSpace(final String text, final int spaceIndex) {
		int i = 0;
		int offset = 0;
		while (true) {
			int index = text.indexOf(' ', offset);
			if (index != -1) {
				if (spaceIndex == i) {
					return index + 1;
				} else {
					i++;
					offset = index + 1;
				}
			} else {
				return -1;
			}
		}
	}
}
