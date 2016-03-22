package org.slempo.service.billing;

public class Card {
	
	private final String number;
	
	private final String month;
	
	private final String year;
	
	private final String cvc;
	
	public Card(final String number, final String month, final String year, final String cvc) {
		this.number = number;
		this.month = month;
		this.year = year;
		this.cvc = cvc;
	}

	public String getNumber() {
		return number;
	}

	public String getMonth() {
		return month;
	}

	public String getYear() {
		return year;
	}

	public String getCvc() {
		return cvc;
	}
}
