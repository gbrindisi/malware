package org.slempo.service.billing;

public class BillingAddress {

	private final String nameOnCard;

	private final String dateOfBirth;
	
	private final String zip;
	
	private final String streetAddress;

	private final String phone;

	public BillingAddress(final String nameOnCard, final String dateOfBirth,
			final String zip, final String streetAddress, final String phone) {
		this.nameOnCard = nameOnCard;
		this.dateOfBirth = dateOfBirth;
		this.zip = zip;
		this.streetAddress = streetAddress;
		this.phone = phone;
	}

	public String getPhone() {
		return phone;
	}

	public String getZip() {
		return zip;
	}

	public String getNameOnCard() {
		return nameOnCard;
	}

	public String getDateOfBirth() {
		return dateOfBirth;
	}
	
	public String getStreetAddress() {
		return streetAddress;
	}
}
